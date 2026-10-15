// Fast heuristic strength score (0–4) for list/detail badges. Watchtower uses zxcvbn for the
// thorough check; this keeps zxcvbn's ~800 KB of dictionaries out of the popup.
const COMMON = new Set(
  "password,123456,123456789,qwerty,12345678,111111,1234567890,1234567,password1,12345,123123,000000,iloveyou,1234,1q2w3e4r,qwertyuiop,123321,monkey,dragon,654321,666666,123,myspace1,a1b2c3,1qaz2wsx,letmein,welcome,admin,abc123,football,baseball,sunshine,princess,qwerty123,zaq12wsx,passw0rd,master,login,starwars,trustno1,whatever,shadow,superman,michael,hello,charlie,freedom,qazwsx,ashley,bailey,access,flower,mustang,killer,hunter,hunter2,jordan,nicole,daniel,jessica,pepper,secret,cheese,ginger,summer,computer,changeme,default,guest,root,test,test123,pass,pass123,password123,йцукен,пароль,qwe123,1q2w3e,asdfgh,zxcvbn,asdf,zxcvbnm,qwertyu"
    .split(","),
);

export type Strength = 0 | 1 | 2 | 3 | 4;
export const STRENGTH_LABEL = ["Very weak", "Weak", "Fair", "Good", "Strong"] as const;
/** Keyguard's score badge values (0..1) for blending the badge color. */
export const STRENGTH_SCORE = [0, 0.2, 0.5, 0.9, 1] as const;

export function quickStrength(pw: string | null | undefined): Strength {
  if (!pw) return 0;
  const lower = pw.toLowerCase();
  if (COMMON.has(lower) || COMMON.has(lower.replace(/[0-9!@#$%^&*]+$/, ""))) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  if (/[^\x00-\x7f]/.test(pw)) pool += 40;
  // Penalise repeats and simple sequences.
  let effective = 0;
  for (let i = 0; i < pw.length; i++) {
    const c = pw.charCodeAt(i), p = pw.charCodeAt(i - 1), pp = pw.charCodeAt(i - 2);
    if (i > 0 && c === p) effective += 0.25;
    else if (i > 1 && c - p === p - pp && Math.abs(c - p) === 1) effective += 0.35;
    else effective += 1;
  }
  const bits = effective * Math.log2(Math.max(pool, 2));
  if (bits < 28) return 0;
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}
