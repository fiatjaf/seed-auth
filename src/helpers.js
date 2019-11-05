/** @format */

export function parselnurl(str) {
  try {
    return str.toLowerCase().match(/lnurl\w+/)[0]
  } catch (e) {}
}
