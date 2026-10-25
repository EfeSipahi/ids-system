// Sets the colour theme chosen in this browser before the page is drawn,
// so that a dark page does not flash light first. app.js offers the choice.
"use strict";
try {
  const theme = localStorage.getItem("ids.theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch (e) {
  // No storage: the system theme.
}
