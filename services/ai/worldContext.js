/**
 * What is going on outside the restaurant.
 *
 * An assistant that only knows the hotel's own numbers can tell you what
 * happened; it cannot tell you that tomorrow is a Sawan Monday, that Onam
 * listings are running in every city magazine, or that the state has just
 * started a food-safety crackdown. Those are the things that change what an
 * owner should cook, staff and decorate for — and none of them are in the
 * database.
 *
 * Three sources, all free and all keyless:
 *
 *   calendar  A computed Indian festival calendar. Deterministic, because a
 *             language model asked "when is Diwali" will answer confidently
 *             and often wrongly, and the whole feature rests on that date.
 *   news      Google News RSS, scoped to the restaurant's own city. No key, no
 *             quota. Gemini's `googleSearch` grounding would be the obvious
 *             tool here and it is not available on the free tier — every
 *             grounded call comes back 429 while plain calls succeed.
 *   clock     Today, the weekday, and where it sits in the month. Cheap, and
 *             the model cannot be trusted to know the date on its own.
 */
import logger from "../../utils/logger.js";

/* ── Calendar ─────────────────────────────────────────────────────────── */

/**
 * Fixed-date observances. Anything tied to the Gregorian calendar is exact.
 *
 * The lunar festivals below are listed per-year rather than computed: deriving
 * Diwali from first principles needs a full panchang implementation, and a
 * table that is obviously a table is easier to correct than arithmetic that is
 * subtly wrong. Extend `LUNAR_FESTIVALS` each year.
 */
const FIXED_FESTIVALS = [
  { month: 1, day: 1, name: "New Year's Day", kind: "national" },
  { month: 1, day: 14, name: "Makar Sankranti / Pongal", kind: "harvest" },
  { month: 1, day: 26, name: "Republic Day", kind: "national" },
  { month: 5, day: 1, name: "Maharashtra Day", kind: "regional", states: ["Maharashtra"] },
  { month: 8, day: 15, name: "Independence Day", kind: "national" },
  { month: 10, day: 2, name: "Gandhi Jayanti", kind: "national" },
  { month: 12, day: 25, name: "Christmas", kind: "national" },
];

/**
 * Lunar and solar-calendar festivals, by year.
 *
 * Only the years the app is realistically in use for. When a year is missing
 * the calendar degrades to fixed festivals and weekday context rather than
 * inventing dates.
 */
const LUNAR_FESTIVALS = {
  2026: [
    { date: "2026-03-04", name: "Holi", kind: "major" },
    { date: "2026-03-21", name: "Eid al-Fitr", kind: "major" },
    { date: "2026-03-26", name: "Ram Navami", kind: "religious" },
    { date: "2026-04-01", name: "Mahavir Jayanti", kind: "religious" },
    { date: "2026-05-01", name: "Buddha Purnima", kind: "religious" },
    { date: "2026-05-27", name: "Eid al-Adha", kind: "major" },
    { date: "2026-08-26", name: "Raksha Bandhan", kind: "major" },
    { date: "2026-09-04", name: "Janmashtami", kind: "major" },
    { date: "2026-09-14", name: "Ganesh Chaturthi", kind: "major", states: ["Maharashtra"] },
    { date: "2026-08-26", name: "Onam", kind: "harvest", states: ["Kerala"] },
    { date: "2026-10-11", name: "Navratri begins", kind: "major" },
    { date: "2026-10-20", name: "Dussehra", kind: "major" },
    { date: "2026-11-08", name: "Diwali", kind: "major" },
    { date: "2026-11-24", name: "Guru Nanak Jayanti", kind: "religious" },
  ],
  2027: [
    { date: "2027-03-22", name: "Holi", kind: "major" },
    { date: "2027-08-15", name: "Raksha Bandhan", kind: "major" },
    { date: "2027-09-03", name: "Ganesh Chaturthi", kind: "major", states: ["Maharashtra"] },
    { date: "2027-10-29", name: "Diwali", kind: "major" },
  ],
};

/**
 * Shravan (Sawan) — roughly late July to late August.
 *
 * Its Mondays matter commercially: a large share of diners fast, which moves
 * demand sharply towards farali food (sabudana khichdi, rajgira, singhara) and
 * away from grain and non-vegetarian dishes. A restaurant that misses this
 * cooks the wrong menu for four Mondays running.
 */
const SHRAVAN_WINDOWS = {
  2026: { from: "2026-07-29", to: "2026-08-27" },
  2027: { from: "2027-07-19", to: "2027-08-17" },
};

const iso = (date) => {
  const local = new Date(date);
  local.setMinutes(local.getMinutes() - local.getTimezoneOffset());
  return local.toISOString().slice(0, 10);
};

const daysBetween = (a, b) =>
  Math.round((new Date(`${b}T00:00:00`) - new Date(`${a}T00:00:00`)) / 86_400_000);

/** Festivals within `window` days either side of today, nearest first. */
const festivalsAround = (today, window = 10) => {
  const year = Number(today.slice(0, 4));

  const fixed = [year - 1, year, year + 1].flatMap((y) =>
    FIXED_FESTIVALS.map((f) => ({
      ...f,
      date: `${y}-${String(f.month).padStart(2, "0")}-${String(f.day).padStart(2, "0")}`,
    }))
  );

  const lunar = [
    ...(LUNAR_FESTIVALS[year - 1] ?? []),
    ...(LUNAR_FESTIVALS[year] ?? []),
    ...(LUNAR_FESTIVALS[year + 1] ?? []),
  ];

  return [...fixed, ...lunar]
    .map((f) => ({ ...f, inDays: daysBetween(today, f.date) }))
    .filter((f) => Math.abs(f.inDays) <= window)
    .sort((a, b) => Math.abs(a.inDays) - Math.abs(b.inDays));
};

const shravanContext = (today) => {
  const window = SHRAVAN_WINDOWS[Number(today.slice(0, 4))];
  if (!window || today < window.from || today > window.to) return null;

  const weekday = new Date(`${today}T00:00:00`).getDay();
  return {
    period: "Shravan (Sawan)",
    isFastingDay: weekday === 1,
    note:
      weekday === 1
        ? "Today is a Sawan Monday — many diners fast, so farali dishes (sabudana, rajgira, singhara, fruit) sell hard and grain or non-veg dishes fall away."
        : "Shravan is running. Vegetarian demand is elevated and many diners avoid non-vegetarian food for the month.",
  };
};

/** Everything the model needs to reason about *when* it is. */
export const calendarContext = (today = iso(new Date())) => {
  const date = new Date(`${today}T00:00:00`);
  const tomorrow = iso(new Date(date.getTime() + 86_400_000));

  const dayNames = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
  ];
  const lastOfMonth = new Date(date.getFullYear(), date.getMonth() + 1, 0).getDate();

  return {
    today,
    tomorrow,
    weekday: dayNames[date.getDay()],
    tomorrowWeekday: dayNames[(date.getDay() + 1) % 7],
    isWeekend: [0, 6].includes(date.getDay()),
    // Payday and month-end both move restaurant footfall noticeably.
    partOfMonth:
      date.getDate() <= 7
        ? "start of month (just after payday — spending runs high)"
        : date.getDate() > lastOfMonth - 5
          ? "end of month (wallets are tight)"
          : "mid-month",
    festivals: festivalsAround(today),
    season: shravanContext(today),
  };
};

/* ── Live news ────────────────────────────────────────────────────────── */

/**
 * Cached per query, because a restaurant's local news does not change minute
 * to minute and the owner may ask a dozen questions in a sitting.
 */
const newsCache = new Map();
const NEWS_TTL_MS = 60 * 60 * 1000;

const stripTags = (value) =>
  String(value ?? "")
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&nbsp;/g, " ")
    .trim();

const parseRssTitles = (xml, limit) => {
  const items = xml.split("<item>").slice(1, limit + 1);
  return items
    .map((item) => {
      const title = item.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/)?.[1];
      const source = item.match(/<source[^>]*>([\s\S]*?)<\/source>/)?.[1];
      const date = item.match(/<pubDate>([\s\S]*?)<\/pubDate>/)?.[1];
      if (!title) return null;
      return {
        headline: stripTags(title),
        source: stripTags(source) || undefined,
        publishedAt: date ? new Date(date).toISOString().slice(0, 10) : undefined,
      };
    })
    .filter(Boolean);
};

const fetchFeed = async (query, limit) => {
  const cached = newsCache.get(query);
  if (cached && Date.now() - cached.at < NEWS_TTL_MS) return cached.items;

  const url =
    "https://news.google.com/rss/search?q=" +
    encodeURIComponent(query) +
    "&hl=en-IN&gl=IN&ceid=IN:en";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      // Google News serves an empty feed to an unrecognised agent.
      headers: { "User-Agent": "Mozilla/5.0 (compatible; QRDine/1.0)" },
    });
    if (!response.ok) throw new Error(`feed returned ${response.status}`);

    const items = parseRssTitles(await response.text(), limit);
    newsCache.set(query, { at: Date.now(), items });
    return items;
  } catch (err) {
    // News is enrichment, never a dependency: a dead feed must not take the
    // assistant down with it.
    logger.warn({ err: err.message, query }, "news feed unavailable");
    return cached?.items ?? [];
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Live signals worth knowing about, scoped to where the restaurant actually is.
 *
 * @param {string} city  Free text from the hotel's address.
 */
export const localNews = async (city) => {
  const place = String(city ?? "India").trim() || "India";

  const [local, dining, events] = await Promise.all([
    fetchFeed(`${place} when:7d`, 6),
    fetchFeed(`${place} restaurants OR food OR dining when:14d`, 6),
    fetchFeed(`India festival OR cricket OR holiday when:7d`, 6),
  ]);

  return { place, local, dining, events };
};

/**
 * Best-effort city from a free-text address.
 *
 * Addresses here are written by hand ("12 Linking Road, Bandra West, Mumbai
 * 400050"), so this takes the last segment that is not a postcode. Wrong
 * guesses cost a slightly less local news feed, nothing more.
 */
export const cityFromLocation = (location) => {
  if (!location) return null;
  const parts = String(location)
    .split(",")
    .map((part) => part.replace(/\b\d{6}\b/g, "").trim())
    .filter(Boolean);
  return parts[parts.length - 1] || null;
};

/** The whole outside-world picture, ready to drop into a prompt. */
export const worldContext = async ({ location } = {}) => {
  const city = cityFromLocation(location);
  const [news] = await Promise.all([localNews(city ?? "India")]);
  return { calendar: calendarContext(), news };
};

export default worldContext;
