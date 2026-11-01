/// Render a compact, deterministic two-column count table for terminal output.
pub(crate) fn render_count_table(rows: impl IntoIterator<Item = (String, usize)>) -> String {
    let mut rows: Vec<_> = rows.into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let label_width = rows
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0)
        .max("Причина".chars().count());
    let count_width = rows
        .iter()
        .map(|(_, count)| count.to_string().len())
        .max()
        .unwrap_or(0)
        .max("Количество".chars().count());

    let top = format!(
        "    ┌{}┬{}┐",
        "─".repeat(label_width + 2),
        "─".repeat(count_width + 2)
    );
    let header = format!(
        "    │ {:<label_width$} │ {:>count_width$} │",
        "Причина", "Количество"
    );
    let divider = format!(
        "    ├{}┼{}┤",
        "─".repeat(label_width + 2),
        "─".repeat(count_width + 2)
    );
    let mut lines = vec![top, header, divider];
    lines.extend(rows.into_iter().map(|(label, count)| {
        format!("    │ {:<label_width$} │ {:>count_width$} │", label, count)
    }));
    lines.push(format!(
        "    └{}┴{}┘",
        "─".repeat(label_width + 2),
        "─".repeat(count_width + 2)
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::render_count_table;

    #[test]
    fn count_table_aligns_columns_and_sorts_by_count_then_label() {
        let table = render_count_table([
            ("vmess: transport=http".to_owned(), 7),
            ("bad uuid".to_owned(), 241),
            ("ssr: feature=ssr".to_owned(), 1),
            ("bad encryption".to_owned(), 241),
        ]);
        let lines: Vec<_> = table.lines().collect();

        assert_eq!(lines.len(), 8);
        assert!(lines
            .iter()
            .all(|line| line.chars().count() == lines[0].chars().count()));
        assert!(lines[3].contains("bad encryption"));
        assert!(lines[4].contains("bad uuid"));
        assert!(lines[5].contains("vmess: transport=http"));
        assert!(lines[6].contains("ssr: feature=ssr"));
        assert!(lines[7].starts_with("    └"));
    }
}
