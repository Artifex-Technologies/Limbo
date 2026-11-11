//! Go's text/tabwriter as the CLI configures it (`tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)`): cells end at a tab, a
//! column block is the run of consecutive lines that have a cell in that column, each column as wide as its widest
//! cell (in runes) plus 2, the last cell of a line not aligned. A line with no tab flushes what came before.

const PADDING: usize = 2;

struct Cell {
    text: Vec<u8>,
    width: usize,
}

/// Formats everything written to one Writer, then Flush.
pub fn format(text: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    let mut lines: Vec<Vec<Cell>> = vec![vec![]];
    let mut cell: Vec<u8> = vec![];
    let width = rune_count;
    for &c in text {
        match c {
            b'\t' | b'\x0b' => {
                let w = width(&cell);
                lines.last_mut().unwrap().push(Cell { text: std::mem::take(&mut cell), width: w });
            }
            b'\n' | b'\x0c' => {
                let w = width(&cell);
                lines.last_mut().unwrap().push(Cell { text: std::mem::take(&mut cell), width: w });
                let ncells = lines.last().unwrap().len();
                lines.push(vec![]);
                if c == b'\x0c' || ncells == 1 {
                    flush(&mut lines, &mut out);
                }
            }
            _ => cell.push(c),
        }
    }
    // Flush: the cell in progress ends the last line
    let w = width(&cell);
    if !cell.is_empty() {
        lines.last_mut().unwrap().push(Cell { text: cell, width: w });
    }
    flush(&mut lines, &mut out);
    out
}

/// utf8.RuneCount
fn rune_count(b: &[u8]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        let len = match std::str::from_utf8(&b[i..(i + 4).min(b.len())]) {
            Ok(s) => s.chars().next().map_or(1, |c| c.len_utf8()),
            Err(e) if e.valid_up_to() > 0 => {
                std::str::from_utf8(&b[i..i + e.valid_up_to()]).unwrap().chars().next().map_or(1, |c| c.len_utf8())
            }
            Err(_) => 1,
        };
        i += len;
        n += 1;
    }
    n
}

fn flush(lines: &mut Vec<Vec<Cell>>, out: &mut Vec<u8>) {
    let all = std::mem::replace(lines, vec![vec![]]);
    let mut widths: Vec<usize> = vec![];
    let n = all.len();
    fmt_block(&all, 0, n, &mut widths, out);
}

fn write_lines(lines: &[Vec<Cell>], from: usize, to: usize, widths: &[usize], out: &mut Vec<u8>) {
    for (i, line) in lines.iter().enumerate().take(to).skip(from) {
        for (j, c) in line.iter().enumerate() {
            out.extend_from_slice(&c.text);
            if j < widths.len() {
                out.extend(std::iter::repeat_n(b' ', widths[j].saturating_sub(c.width)));
            }
        }
        if i + 1 == lines.len() {
            // the last buffered line has no newline of its own
        } else {
            out.push(b'\n');
        }
    }
}

fn fmt_block(lines: &[Vec<Cell>], mut line0: usize, line1: usize, widths: &mut Vec<usize>, out: &mut Vec<u8>) {
    let column = widths.len();
    let mut this = line0;
    while this < line1 {
        if column + 1 >= lines[this].len() {
            this += 1;
            continue;
        }
        write_lines(lines, line0, this, widths, out);
        line0 = this;
        let mut width = 0;
        while this < line1 {
            let line = &lines[this];
            if column + 1 >= line.len() {
                break;
            }
            width = width.max(line[column].width + PADDING);
            this += 1;
        }
        widths.push(width);
        fmt_block(lines, line0, this, widths, out);
        widths.pop();
        line0 = this;
    }
    write_lines(lines, line0, line1, widths, out);
}
