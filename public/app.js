let modes = {
  sqlInjectionEnabled: false,
  loginAttemptLimitDisabled: false,
  revealingAuthErrorsEnabled: false,
};
let sessionToken;

const modeToggles = [...document.querySelectorAll("[data-mode]")];
const searchForm = document.querySelector("#search-form");
const searchInput = document.querySelector("#search-input");
const searchStatus = document.querySelector("#search-status");
const searchResults = document.querySelector("#search-results");
const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");
const profile = document.querySelector("#profile");
const logoutButton = document.querySelector("#logout-button");

async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers ?? {}),
    },
  });

  if (response.status === 204) {
    return null;
  }

  const body = await response.json();
  if (!response.ok) {
    const error = new Error(body.error ?? `Zahtjev nije uspio (${response.status}).`);
    error.status = response.status;
    error.details = body;
    throw error;
  }
  return body;
}

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle("error", isError);
}

function renderRows(rows) {
  searchResults.replaceChildren();
  if (rows.length === 0) {
    searchResults.textContent = "Nema pronađenih korisnika.";
    return;
  }

  const table = document.createElement("table");
  const header = table.createTHead().insertRow();
  for (const label of ["Korisničko ime", "Prikazno ime", "Uloga"]) {
    const cell = document.createElement("th");
    cell.textContent = label;
    header.append(cell);
  }

  const body = table.createTBody();
  for (const user of rows) {
    const row = body.insertRow();
    for (const value of [user.username, user.displayName, user.role]) {
      const cell = row.insertCell();
      cell.textContent = value;
    }
  }
  searchResults.append(table);
}

async function updateModes() {
  modes = await api("/api/modes");
  for (const toggle of modeToggles) {
    toggle.checked = modes[toggle.dataset.mode];
  }
}

async function changeMode(key, enabled, checkbox) {
  const previous = modes[key];
  modes = { ...modes, [key]: enabled };
  try {
    modes = await api("/api/modes", {
      method: "PATCH",
      body: JSON.stringify({ [key]: enabled }),
    });
    for (const toggle of modeToggles) {
      toggle.checked = modes[toggle.dataset.mode];
    }
  } catch (error) {
    modes = { ...modes, [key]: previous };
    checkbox.checked = previous;
    setStatus(loginStatus, error.message, true);
  }
}

for (const toggle of modeToggles) {
  toggle.addEventListener("change", () => {
    void changeMode(toggle.dataset.mode, toggle.checked, toggle);
  });
}

searchForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus(searchStatus, "Pretraživanje...");
  try {
    const result = await api("/api/sql-search", {
      method: "POST",
      body: JSON.stringify({ search: searchInput.value }),
    });
    renderRows(result.rows);
    setStatus(
      searchStatus,
      result.demonstration === "tautology"
        ? "Ranjivi način: tautološki unos demonstracijski vraća sve sintetičke račune."
        : result.mode === "vulnerable"
          ? "Ranjivi način je uključen. Unesi tautološki izraz u polje za pretragu."
        : "Zaštićeni način: korisnički unos poslan je kao SQL parametar.",
    );
  } catch (error) {
    setStatus(searchStatus, error.message, true);
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus(loginStatus, "Provjera...");
  profile.hidden = true;
  logoutButton.hidden = true;
  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: document.querySelector("#username-input").value,
        password: document.querySelector("#password-input").value,
      }),
    });
    sessionToken = result.token;
    profile.textContent =
      `Prijavljeni korisnik: ${result.user.displayName} · ` +
      `uloga: ${result.user.role}`;
    profile.hidden = false;
    logoutButton.hidden = false;
    setStatus(loginStatus, result.message);
  } catch (error) {
    sessionToken = undefined;
    const attempts = error.details?.attempts;
    setStatus(
      loginStatus,
      attempts
        ? `${error.message} Neuspješni pokušaji: ${attempts}.`
        : error.message,
      true,
    );
  }
});

logoutButton.addEventListener("click", async () => {
  try {
    const result = await api("/api/session", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    sessionToken = undefined;
    profile.hidden = true;
    logoutButton.hidden = true;
    setStatus(loginStatus, result.message, !result.revoked);
  } catch (error) {
    setStatus(loginStatus, error.message, true);
  }
});

document
  .querySelector("#reset-attempts-button")
  .addEventListener("click", async () => {
    try {
      const result = await api("/api/login/reset-demo", { method: "POST" });
      setStatus(loginStatus, result.message);
    } catch (error) {
      setStatus(loginStatus, error.message, true);
    }
  });

updateModes().catch((error) => {
  setStatus(searchStatus, error.message, true);
  setStatus(loginStatus, "Pokrenite lokalni poslužitelj i osvježite stranicu.", true);
});
