// Front coding for sorted word lists, the scheme zxcvbn-ts ships its dictionaries in: each word
// is a capital letter A–Z saying how many characters it shares with the previous word (0–25),
// then the rest of the word. Words must not contain capital letters.

export function frontCode(words: string[]): string {
  let s = "";
  let last = "";
  for (const w of words) {
    if (/[A-Z]/.test(w)) throw new Error(`Word with a capital letter: ${w}`);
    let p = 0;
    while (p < 25 && p < last.length && last[p] === w[p]) p++;
    s += String.fromCharCode(65 + p) + w.slice(p);
    last = w;
  }
  return s;
}

export function unFrontCode(s: string): string[] {
  const parts = s.split(/([A-Z])/);
  const words: string[] = [];
  let last = "";
  for (let i = 1; i < parts.length; i += 2) {
    last = last.slice(0, parts[i].charCodeAt(0) - 65) + parts[i + 1];
    words.push(last);
  }
  return words;
}
