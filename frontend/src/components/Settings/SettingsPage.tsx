import { useStore, type Theme } from '../../state/store';

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
];

export function SettingsPage() {
  const theme = useStore((s) => s.theme);
  const setTheme = useStore((s) => s.setTheme);

  return (
    <div className="settings-page">
      <div className="settings-page__header">
        <h1 className="settings-page__title">Settings</h1>
      </div>

      <div className="settings-page__content">
        <section className="settings-section">
          <h2 className="settings-section__title">Appearance</h2>

          <div className="settings-item">
            <div className="settings-item__info">
              <span className="settings-item__label">Theme</span>
              <span className="settings-item__description">
                Choose between light and dark mode
              </span>
            </div>
            <div className="settings-item__control">
              <select
                className="settings-select"
                value={theme}
                onChange={(e) => setTheme(e.target.value as Theme)}
                aria-label="Theme"
              >
                {THEME_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </section>

        <section className="settings-section">
          <h2 className="settings-section__title">Security</h2>

          <div className="settings-item">
            <div className="settings-item__info">
              <span className="settings-item__label">FIDO2 / WebAuthn</span>
              <span className="settings-item__description">
                Manage your security keys for passwordless authentication
              </span>
            </div>
            <div className="settings-item__control">
              <button type="button" className="settings-button">
                Manage Keys
              </button>
            </div>
          </div>
        </section>

        <section className="settings-section">
          <h2 className="settings-section__title">About</h2>

          <div className="settings-item">
            <div className="settings-item__info">
              <span className="settings-item__label">go-signal</span>
              <span className="settings-item__description">
                A Signal-compatible messaging client
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
