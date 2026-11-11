//! UI wiring for public proxy-source discovery and collection.
//!
//! The discovery database is deliberately separate from the VPN/proxy run
//! settings. Search keys stay in SQLite and are never copied into Slint models.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::StreamExt;
use slint::{ComponentHandle, ModelRc, SharedString};

use crate::{
    app::{
        AppWindow, ProxyFinderProvider, ProxySavedSource, ProxySearchEngine, ProxySearchQuery,
        ProxySearchResult,
    },
    proxy_collection::{
        collect_proxy_sources, CollectedProxy, ProxyCollectionProgressCallback,
        ProxySourceSelection,
    },
    proxy_grabber::{
        DiscoveryItem, NewSearchQuery, ProxyGrabberStore, SourceClassification, UpdateSearchQuery,
    },
    proxy_search::{self, SearchCredentials, SearchProvider, SearchResult},
};

const SEARCH_TIMEOUT: Duration = Duration::from_secs(20);
const SEARCH_RESULTS_PER_REQUEST: usize = 10;
const SEARCH_CONCURRENCY: usize = 4;
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(10);
const COLLECTION_CONCURRENCY: usize = 32;

#[derive(Clone)]
struct SavedHit {
    query_id: i64,
    result: SearchResult,
}

#[derive(Default)]
struct FinderState {
    selected_sources: HashSet<i64>,
    hits_by_url: HashMap<String, SavedHit>,
    search_rows: Vec<ProxySearchResult>,
    collected: Vec<CollectedProxy>,
}

/// Connect the proxy-discovery page to its local persistence and network
/// adapters. Call once after `AppWindow` has been created.
pub fn wire(window: &AppWindow, data_dir: &Path) -> Result<()> {
    let store = ProxyGrabberStore::open(data_dir.join("proxy-finder.sqlite3"))?;
    seed_queries_if_empty(&store)?;

    let state = Arc::new(Mutex::new(FinderState::default()));
    let selected_engines = load_selected_engines(&store);
    store.set_preference(
        "selected_engines",
        &serde_json::to_string(&selected_engines)?,
    )?;
    render_queries(window, &store)?;
    render_engines(window, &selected_engines);
    render_providers(window, &store)?;
    render_sources(window, &store, &state)?;
    let no_results = Vec::<ProxySearchResult>::new();
    window.set_proxy_search_results(ModelRc::from(no_results.as_slice()));
    let no_errors = Vec::<SharedString>::new();
    window.set_proxy_search_errors(ModelRc::from(no_errors.as_slice()));
    window.set_proxy_search_status("Поиск готов к запуску".into());
    window.set_proxy_progress_done(0);
    window.set_proxy_progress_total(0);
    window.set_proxy_progress_rate("—".into());
    window.set_proxy_collected_node_count("0".into());

    let weak = window.as_weak();
    let callback_store = store.clone();
    window.on_proxy_finder_query_edited(move |id, query| {
        let Some(window) = weak.upgrade() else { return };
        let Ok(id) = id.as_str().parse::<i64>() else {
            return;
        };
        if let Err(error) = update_query_text(&callback_store, id, query.as_str()) {
            set_errors(
                &window,
                vec![format!("Не удалось сохранить запрос: {error}")],
            );
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    window.on_proxy_finder_query_enabled_changed(move |id, enabled| {
        let Some(window) = weak.upgrade() else { return };
        let Ok(id) = id.as_str().parse::<i64>() else {
            return;
        };
        if let Err(error) = update_query_enabled(&callback_store, id, enabled) {
            set_errors(
                &window,
                vec![format!("Не удалось обновить запрос: {error}")],
            );
        } else {
            let _ = render_queries(&window, &callback_store);
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    window.on_proxy_finder_query_added(move || {
        let Some(window) = weak.upgrade() else { return };
        let query = NewSearchQuery {
            query: "\"socks5://\" proxy list".into(),
            provider: "all".into(),
            title: "Новый запрос".into(),
            active: true,
        };
        match callback_store.add_query(&query) {
            Ok(_) => {
                let _ = render_queries(&window, &callback_store);
                set_errors(&window, Vec::new());
            }
            Err(error) => set_errors(
                &window,
                vec![format!("Не удалось добавить запрос: {error}")],
            ),
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    let callback_state = state.clone();
    window.on_proxy_finder_query_removed(move |id| {
        let Some(window) = weak.upgrade() else { return };
        let Ok(id) = id.as_str().parse::<i64>() else {
            return;
        };
        match callback_store.delete_query(id) {
            Ok(_) => {
                let _ = render_queries(&window, &callback_store);
                let _ = render_sources(&window, &callback_store, &callback_state);
            }
            Err(error) => set_errors(&window, vec![format!("Не удалось удалить запрос: {error}")]),
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    let callback_state = state.clone();
    window.on_proxy_finder_engine_toggled(move |id, selected| {
        if let Some(window) = weak.upgrade() {
            update_engine_selection(
                &window,
                &callback_store,
                &callback_state,
                id.as_str(),
                Some(selected),
            );
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    let callback_state = state.clone();
    window.on_proxy_finder_engines_select_all(move |selected| {
        if let Some(window) = weak.upgrade() {
            update_engine_selection(
                &window,
                &callback_store,
                &callback_state,
                "",
                Some(selected),
            );
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    window.on_proxy_finder_provider_credential_save(move |provider, secret| {
        let Some(window) = weak.upgrade() else { return };
        let provider_id = provider.as_str();
        match callback_store.set_credential(provider_id, secret.as_str()) {
            Ok(()) => {
                // Never echo the secret into UI state, errors, or logs.
                let _ = render_providers(&window, &callback_store);
                window.set_proxy_search_status(
                    format!("Ключ {} сохранён локально", provider_label(provider_id)).into(),
                );
                set_errors(&window, Vec::new());
            }
            Err(error) => set_errors(
                &window,
                vec![format!("Не удалось сохранить ключ провайдера: {error}")],
            ),
        }
    });

    let weak = window.as_weak();
    window.on_proxy_finder_provider_action(move |provider| {
        if let Some(window) = weak.upgrade() {
            window.set_proxy_search_status(
                format!(
                    "Введите или обновите ключ для {} в поле ниже",
                    provider_label(provider.as_str())
                )
                .into(),
            );
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    let callback_state = state.clone();
    window.on_proxy_finder_search(move || {
        let Some(window) = weak.upgrade() else { return };
        if window.get_proxy_searching() {
            return;
        }
        let queries = match callback_store.list_queries(true) {
            Ok(queries) => queries,
            Err(error) => {
                set_errors(
                    &window,
                    vec![format!("Не удалось загрузить запросы: {error}")],
                );
                return;
            }
        };
        let engines = match read_selected_engines(&callback_store) {
            Ok(engines) => engines,
            Err(error) => {
                set_errors(
                    &window,
                    vec![format!("Не удалось загрузить поисковики: {error}")],
                );
                return;
            }
        };
        if queries.is_empty() {
            set_errors(
                &window,
                vec!["Включите или добавьте хотя бы один поисковый запрос.".into()],
            );
            return;
        }
        if engines.is_empty() {
            set_errors(
                &window,
                vec!["Выберите хотя бы одну поисковую систему.".into()],
            );
            return;
        }
        let credentials = match read_credentials(&callback_store) {
            Ok(credentials) => credentials,
            Err(error) => {
                set_errors(
                    &window,
                    vec![format!("Не удалось прочитать локальные ключи: {error}")],
                );
                return;
            }
        };
        window.set_proxy_searching(true);
        window.set_proxy_search_status("Идёт поиск по выбранным системам…".into());
        let no_results = Vec::<ProxySearchResult>::new();
        window.set_proxy_search_results(ModelRc::from(no_results.as_slice()));
        set_errors(&window, Vec::new());
        let weak = window.as_weak();
        let store = callback_store.clone();
        let state = callback_state.clone();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let message = format!("Не удалось запустить поиск: {error}");
                    let _ = weak.upgrade_in_event_loop(move |window| {
                        window.set_proxy_searching(false);
                        window.set_proxy_search_status("Поиск не запущен".into());
                        set_errors(&window, vec![message]);
                    });
                    return;
                }
            };
            let jobs = queries
                .into_iter()
                .flat_map(|query| {
                    engines
                        .iter()
                        .copied()
                        .map(move |provider| (query.clone(), provider))
                })
                .collect::<Vec<_>>();
            let credentials_for_jobs = credentials.clone();
            let completed = runtime.block_on(async move {
                futures::stream::iter(jobs.into_iter().map(|(query, provider)| {
                    let credentials = credentials_for_jobs.clone();
                    async move {
                        let result = proxy_search::search(
                            provider,
                            &query.query,
                            &credentials,
                            SEARCH_RESULTS_PER_REQUEST,
                            SEARCH_TIMEOUT,
                        )
                        .await;
                        (query, provider, result)
                    }
                }))
                .buffer_unordered(SEARCH_CONCURRENCY)
                .collect::<Vec<_>>()
                .await
            });

            let mut errors = Vec::new();
            let mut result_by_url = HashMap::<String, SavedHit>::new();
            for (query, provider, result) in completed {
                match result {
                    Ok(hits) => {
                        for hit in hits {
                            let key = canonical_url(&hit.url);
                            if !key.is_empty() {
                                result_by_url.entry(key).or_insert_with(|| SavedHit {
                                    query_id: query.id,
                                    result: hit,
                                });
                            }
                        }
                    }
                    Err(error) => errors.push(format!(
                        "{} · «{}»: {}",
                        provider_label(provider.as_str()),
                        query.query,
                        error
                    )),
                }
            }
            let mut hits = result_by_url.into_values().collect::<Vec<_>>();
            hits.sort_by(|a, b| {
                a.result
                    .title
                    .to_lowercase()
                    .cmp(&b.result.title.to_lowercase())
            });
            let ui_results = hits
                .iter()
                .map(|hit| ProxySearchResult {
                    id: SharedString::from(hit.result.url.as_str()),
                    title: SharedString::from(if hit.result.title.trim().is_empty() {
                        hit.result.url.as_str()
                    } else {
                        hit.result.title.as_str()
                    }),
                    url: hit.result.url.clone().into(),
                    engine: provider_label(&hit.result.provider).into(),
                    snippet: hit.result.snippet.clone().into(),
                    saved_snapshot: false,
                    saved_rolling: false,
                })
                .collect::<Vec<_>>();
            let saved_hits = hits
                .into_iter()
                .map(|hit| (canonical_url(&hit.result.url), hit))
                .collect::<HashMap<_, _>>();
            {
                let mut current = state.lock().unwrap_or_else(|poison| poison.into_inner());
                current.hits_by_url = saved_hits;
                current.search_rows = ui_results.clone();
            }
            let status = if ui_results.is_empty() {
                "Поиск завершён: результатов нет".to_owned()
            } else {
                format!("Найдено {} уникальных ссылок", ui_results.len())
            };
            let _ = weak.upgrade_in_event_loop(move |window| {
                window.set_proxy_searching(false);
                window.set_proxy_search_status(status.into());
                window.set_proxy_search_results(ModelRc::from(ui_results.as_slice()));
                set_errors(&window, errors);
                let _ = render_providers(&window, &store);
            });
        });
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    let callback_state = state.clone();
    window.on_proxy_finder_save_result_source(move |url, classification| {
        let Some(window) = weak.upgrade() else { return };
        let class = match classification.as_str() {
            "snapshot" => SourceClassification::Snapshot,
            "rolling" | "rolling_feed" => SourceClassification::RollingFeed,
            _ => {
                set_errors(
                    &window,
                    vec!["Выберите тип сохранения: снимок или обновляемая лента.".into()],
                );
                return;
            }
        };
        let key = canonical_url(url.as_str());
        let hit = callback_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .hits_by_url
            .get(&key)
            .cloned();
        let Some(hit) = hit else {
            set_errors(
                &window,
                vec!["Результат поиска уже устарел. Выполните поиск ещё раз.".into()],
            );
            return;
        };
        let item = DiscoveryItem {
            provider: hit.result.provider.clone(),
            title: hit.result.title.clone(),
            url: hit.result.url.clone(),
            classification: class,
        };
        let saved = callback_store
            .persist_discovery_result(hit.query_id, &[item])
            .context("не удалось сохранить ссылку в базе источников");
        match saved {
            Ok(_) => {
                {
                    let mut current = callback_state
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner());
                    if let Some(row) = current
                        .search_rows
                        .iter_mut()
                        .find(|row| canonical_url(row.url.as_str()) == key)
                    {
                        match class {
                            SourceClassification::Snapshot => row.saved_snapshot = true,
                            SourceClassification::RollingFeed => row.saved_rolling = true,
                        }
                    }
                    window.set_proxy_search_results(ModelRc::from(current.search_rows.as_slice()));
                }
                let _ = render_sources(&window, &callback_store, &callback_state);
                set_errors(&window, Vec::new());
                window.set_proxy_search_status(if class == SourceClassification::Snapshot {
                    "Ссылка сохранена как снимок".into()
                } else {
                    "Ссылка сохранена как обновляемая лента".into()
                });
            }
            Err(error) => set_errors(&window, vec![error.to_string()]),
        }
    });

    let weak = window.as_weak();
    let callback_state = state.clone();
    let callback_store = store.clone();
    window.on_proxy_finder_source_selection_changed(move |id, selected| {
        let Ok(id) = id.as_str().parse::<i64>() else {
            return;
        };
        {
            let mut current = callback_state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if selected {
                current.selected_sources.insert(id);
            } else {
                current.selected_sources.remove(&id);
            }
        }
        if let Some(window) = weak.upgrade() {
            let _ = render_sources(&window, &callback_store, &callback_state);
        }
    });

    let weak = window.as_weak();
    let callback_store = store.clone();
    let callback_state = state.clone();
    window.on_proxy_finder_source_removed(move |id| {
        let Some(window) = weak.upgrade() else { return };
        let Ok(id) = id.as_str().parse::<i64>() else {
            return;
        };
        match callback_store.delete_source(id) {
            Ok(_) => {
                callback_state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .selected_sources
                    .remove(&id);
                let _ = render_sources(&window, &callback_store, &callback_state);
            }
            Err(error) => set_errors(
                &window,
                vec![format!("Не удалось удалить источник: {error}")],
            ),
        }
    });

    for collect_all in [false, true] {
        let weak = window.as_weak();
        let callback_store = store.clone();
        let callback_state = state.clone();
        let start: Arc<dyn Fn()> = Arc::new(move || {
            let Some(window) = weak.upgrade() else { return };
            if window.get_proxy_collecting() {
                return;
            }
            let selection = if collect_all {
                ProxySourceSelection::AllActive
            } else {
                let ids = callback_state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .selected_sources
                    .iter()
                    .copied()
                    .collect::<Vec<_>>();
                if ids.is_empty() {
                    set_errors(
                        &window,
                        vec!["Выберите хотя бы одну сохранённую ссылку.".into()],
                    );
                    return;
                }
                ProxySourceSelection::Ids(ids)
            };
            let source_total = match &selection {
                ProxySourceSelection::Ids(ids) => ids.len(),
                ProxySourceSelection::AllActive => match callback_store.list_sources(true) {
                    Ok(sources) => sources.len(),
                    Err(error) => {
                        set_errors(
                            &window,
                            vec![format!("Не удалось загрузить источники: {error}")],
                        );
                        return;
                    }
                },
            };
            window.set_proxy_collecting(true);
            window.set_proxy_progress_done(0);
            window.set_proxy_progress_total(source_total.min(i32::MAX as usize) as i32);
            window.set_proxy_progress_rate("—".into());
            window.set_proxy_search_status("Загружаем содержимое сохранённых источников…".into());
            set_errors(&window, Vec::new());
            let weak = window.as_weak();
            let store = callback_store.clone();
            let state = callback_state.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                let cumulative_nodes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let rate_nodes = cumulative_nodes.clone();
                let progress_weak = weak.clone();
                let progress: ProxyCollectionProgressCallback = Arc::new(move |event| {
                    let count = rate_nodes
                        .fetch_add(event.valid_count, std::sync::atomic::Ordering::Relaxed)
                        + event.valid_count;
                    let rate = count as f64 / started.elapsed().as_secs_f64().max(0.25);
                    let weak = progress_weak.clone();
                    let _ = weak.upgrade_in_event_loop(move |window| {
                        window.set_proxy_progress_done(event.completed as i32);
                        window.set_proxy_progress_total(event.total as i32);
                        window.set_proxy_progress_rate(format!("{rate:.1}").into());
                        window.set_proxy_collected_node_count(count.to_string().into());
                    });
                });
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let message = format!("Не удалось запустить сбор источников: {error}");
                        let _ = weak.upgrade_in_event_loop(move |window| {
                            window.set_proxy_collecting(false);
                            set_errors(&window, vec![message]);
                        });
                        return;
                    }
                };
                let result = runtime.block_on(collect_proxy_sources(
                    &store,
                    selection,
                    COLLECTION_TIMEOUT,
                    COLLECTION_CONCURRENCY,
                    Some(progress),
                ));
                match result {
                    Ok(report) => {
                        let count = report.proxies.len();
                        state
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .collected = report.proxies;
                        let errors = report.errors;
                        let status =
                            format!("Сбор завершён: {count} уникальных прокси из источников");
                        let _ = weak.upgrade_in_event_loop(move |window| {
                            window.set_proxy_collecting(false);
                            window.set_proxy_search_status(status.into());
                            window.set_proxy_collected_node_count(count.to_string().into());
                            set_errors(&window, errors);
                            let _ = render_sources(&window, &store, &state);
                        });
                    }
                    Err(error) => {
                        let message = format!("Сбор не выполнен: {error}");
                        let _ = weak.upgrade_in_event_loop(move |window| {
                            window.set_proxy_collecting(false);
                            set_errors(&window, vec![message]);
                        });
                    }
                }
            });
        });
        if collect_all {
            let start = start.clone();
            window.on_proxy_finder_collect_all(move || start());
        } else {
            window.on_proxy_finder_collect_selected(move || start());
        }
    }

    let weak = window.as_weak();
    let callback_state = state.clone();
    window.on_proxy_finder_send_collected_to_check(move || {
        let Some(window) = weak.upgrade() else { return };
        let collected = callback_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .collected
            .clone();
        if collected.is_empty() {
            set_errors(
                &window,
                vec!["Сначала соберите прокси хотя бы из одного источника.".into()],
            );
            return;
        }
        // Keep this handoff isolated from the VPN editor. The two checker modes
        // own separate input lists, even when the currently visible field is empty.
        let mut existing = window.get_forward_proxy_links().to_string();
        let mut known = existing
            .lines()
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect::<HashSet<_>>();
        let mut additions = Vec::new();
        for item in collected {
            let uri = item.proxy.original_uri.trim();
            if uri.is_empty() || !known.insert(uri.to_owned()) {
                continue;
            }
            additions.push(format!("# ProxySift-Source: {}", item.source_url));
            additions.push(uri.to_owned());
        }
        if additions.is_empty() {
            set_errors(
                &window,
                vec!["Собранные прокси уже присутствуют в списке проверки.".into()],
            );
            return;
        }
        if !existing.trim().is_empty() {
            existing.push_str("\n");
        }
        existing.push_str(&additions.join("\n"));
        window.set_checker_mode("forward".into());
        window.set_forward_proxy_links(existing.clone().into());
        window.set_proxy_links(existing.into());
        window.invoke_subscriptions_changed();
        window.set_active_page("check".into());
        set_errors(&window, Vec::new());
        window.set_proxy_search_status(
            format!(
                "Добавлено {} прокси в проверку HTTP/SOCKS",
                additions.len() / 2
            )
            .into(),
        );
    });

    let weak = window.as_weak();
    window.on_proxy_finder_clear_errors(move || {
        if let Some(window) = weak.upgrade() {
            set_errors(&window, Vec::new());
        }
    });

    Ok(())
}

fn seed_queries_if_empty(store: &ProxyGrabberStore) -> Result<()> {
    if !store.list_queries(false)?.is_empty() {
        return Ok(());
    }
    for (title, query) in [
        ("HTTP", "\"http proxy\" \"ip:port\" free list"),
        ("HTTPS", "\"https proxy\" \"ip:port\" public list"),
        ("SOCKS4", "\"socks4 proxy\" public list"),
        ("SOCKS5", "\"socks5 proxy\" public list"),
    ] {
        store.add_query(&NewSearchQuery {
            query: query.into(),
            provider: "all".into(),
            title: title.into(),
            active: true,
        })?;
    }
    Ok(())
}

fn update_query_text(store: &ProxyGrabberStore, id: i64, text: &str) -> Result<()> {
    // TextInput emits intermediate states while the user replaces a query.
    // Keep the last valid persisted value until the field becomes non-empty.
    if text.trim().is_empty() {
        return Ok(());
    }
    let Some(query) = store
        .list_queries(false)?
        .into_iter()
        .find(|query| query.id == id)
    else {
        return Ok(());
    };
    store.update_query(
        id,
        &UpdateSearchQuery {
            query: text.to_owned(),
            provider: query.provider,
            title: query.title,
            active: query.active,
        },
    )?;
    Ok(())
}

fn update_query_enabled(store: &ProxyGrabberStore, id: i64, enabled: bool) -> Result<()> {
    let Some(query) = store
        .list_queries(false)?
        .into_iter()
        .find(|query| query.id == id)
    else {
        return Ok(());
    };
    store.update_query(
        id,
        &UpdateSearchQuery {
            query: query.query,
            provider: query.provider,
            title: query.title,
            active: enabled,
        },
    )?;
    Ok(())
}

fn render_queries(window: &AppWindow, store: &ProxyGrabberStore) -> Result<()> {
    let rows = store
        .list_queries(false)?
        .into_iter()
        .map(|query| ProxySearchQuery {
            id: query.id.to_string().into(),
            query: query.query.into(),
            enabled: query.active,
        })
        .collect::<Vec<_>>();
    window.set_proxy_search_queries(ModelRc::from(rows.as_slice()));
    Ok(())
}

fn load_selected_engines(store: &ProxyGrabberStore) -> Vec<String> {
    read_selected_engine_ids(store)
        .unwrap_or_else(|_| provider_ids().iter().map(|id| (*id).to_owned()).collect())
}

fn read_selected_engines(store: &ProxyGrabberStore) -> Result<Vec<SearchProvider>> {
    Ok(read_selected_engine_ids(store)?
        .iter()
        .filter_map(|id| SearchProvider::from_str(id).ok())
        .collect())
}

fn read_selected_engine_ids(store: &ProxyGrabberStore) -> Result<Vec<String>> {
    let selected = store
        .preference("selected_engines")?
        .and_then(|value| serde_json::from_str::<Vec<String>>(&value).ok())
        .unwrap_or_else(|| provider_ids().iter().map(|id| (*id).to_owned()).collect());
    Ok(selected
        .into_iter()
        .filter(|id| SearchProvider::from_str(id).is_ok())
        .collect())
}

fn render_engines(window: &AppWindow, selected: &[String]) {
    let rows = ["google", "yandex", "bing", "duckduckgo", "github", "brave"]
        .into_iter()
        .map(|id| ProxySearchEngine {
            id: id.into(),
            name: provider_label(id).into(),
            selected: selected.iter().any(|item| item == id),
        })
        .collect::<Vec<_>>();
    window.set_proxy_search_engines(ModelRc::from(rows.as_slice()));
}

fn update_engine_selection(
    window: &AppWindow,
    store: &ProxyGrabberStore,
    _state: &Arc<Mutex<FinderState>>,
    id: &str,
    selected: Option<bool>,
) {
    let mut engines = load_selected_engines(store);
    if id.is_empty() {
        engines = if selected.unwrap_or(false) {
            provider_ids().iter().map(|id| (*id).to_owned()).collect()
        } else {
            Vec::new()
        };
    } else if provider_ids().contains(&id) {
        if selected.unwrap_or(false) {
            if !engines.iter().any(|engine| engine == id) {
                engines.push(id.to_owned());
            }
        } else {
            engines.retain(|engine| engine != id);
        }
    }
    if let Ok(value) = serde_json::to_string(&engines) {
        if let Err(error) = store.set_preference("selected_engines", &value) {
            set_errors(
                window,
                vec![format!("Не удалось сохранить выбор поисковиков: {error}")],
            );
            return;
        }
    }
    render_engines(window, &engines);
}

fn render_providers(window: &AppWindow, store: &ProxyGrabberStore) -> Result<()> {
    let configured = store
        .configured_credentials()?
        .into_iter()
        .collect::<HashSet<_>>();
    let rows = [
        (
            "serpapi",
            "Google · Яндекс · Bing · DuckDuckGo",
            "Один ключ SerpApi для четырёх поисковиков",
        ),
        (
            "github",
            "GitHub Code",
            "Поиск публичных файлов с прокси-ссылками",
        ),
        ("brave", "Brave Search", "Независимый веб-поиск"),
    ]
    .into_iter()
    .map(|(id, name, detail)| {
        let ready = configured.contains(id);
        ProxyFinderProvider {
            id: id.into(),
            name: name.into(),
            status: if ready { "ready" } else { "missing" }.into(),
            detail: detail.into(),
            credential_configured: ready,
        }
    })
    .collect::<Vec<_>>();
    window.set_proxy_search_providers(ModelRc::from(rows.as_slice()));
    Ok(())
}

fn read_credentials(store: &ProxyGrabberStore) -> Result<SearchCredentials> {
    Ok(SearchCredentials {
        serpapi_api_key: store.credential("serpapi")?,
        github_token: store.credential("github")?,
        brave_api_key: store.credential("brave")?,
    })
}

fn render_sources(
    window: &AppWindow,
    store: &ProxyGrabberStore,
    state: &Arc<Mutex<FinderState>>,
) -> Result<()> {
    let sources = store.list_sources(false)?;
    let mut current = state.lock().unwrap_or_else(|poison| poison.into_inner());
    let valid_ids = sources
        .iter()
        .map(|source| source.id)
        .collect::<HashSet<_>>();
    current.selected_sources.retain(|id| valid_ids.contains(id));
    let rows = sources
        .into_iter()
        .map(|source| {
            let id = source.id;
            ProxySavedSource {
                id: id.to_string().into(),
                title: if source.title.trim().is_empty() {
                    source.url.clone().into()
                } else {
                    source.title.into()
                },
                url: source.url.into(),
                feed_type: match source.classification {
                    SourceClassification::Snapshot => "snapshot".into(),
                    SourceClassification::RollingFeed => "rolling".into(),
                },
                last_collected: source
                    .last_fetched_at
                    .map(format_timestamp)
                    .unwrap_or_else(|| "Ещё не собиралась".into())
                    .into(),
                last_status: match source.last_fetch_status.as_deref() {
                    Some("success") => "Прокси найдены".into(),
                    Some("unrecognized") => "Формат не распознан".into(),
                    Some("failed") => "Ошибка сбора".into(),
                    Some(status) => status.into(),
                    None => "Не проверялась".into(),
                },
                node_count: source
                    .last_fetch_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "—".into())
                    .into(),
                selected: current.selected_sources.contains(&id),
            }
        })
        .collect::<Vec<_>>();
    window.set_proxy_saved_sources(ModelRc::from(rows.as_slice()));
    Ok(())
}

fn set_errors(window: &AppWindow, errors: Vec<String>) {
    let rows = errors
        .into_iter()
        .map(SharedString::from)
        .collect::<Vec<_>>();
    window.set_proxy_search_errors(ModelRc::from(rows.as_slice()));
}

fn provider_ids() -> &'static [&'static str] {
    &["google", "yandex", "bing", "duckduckgo", "github", "brave"]
}

fn provider_label(provider: &str) -> &'static str {
    match provider {
        "google" => "Google",
        "yandex" => "Яндекс",
        "bing" => "Bing",
        "duckduckgo" => "DuckDuckGo",
        "github" => "GitHub",
        "brave" => "Brave",
        "serpapi" => "SerpApi",
        _ => "поисковик",
    }
}

fn canonical_url(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value.trim()) else {
        return String::new();
    };
    if !matches!(url.scheme(), "http" | "https") {
        return String::new();
    }
    url.set_fragment(None);
    url.to_string().trim_end_matches('/').to_owned()
}

fn format_timestamp(timestamp_ms: i64) -> String {
    crate::database::display_timestamp(timestamp_ms)
}
