import { useStore, type NavTab } from '../state/store';

const TABS: { id: NavTab; label: string; icon: JSX.Element }[] = [
  {
    id: 'chats',
    label: 'Chats',
    icon: (
      <svg className="NavTabs__ItemIcon" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
        <path d="M10 1C5.03 1 1 4.58 1 9c0 1.5.44 2.9 1.2 4.11L1.05 16.5a1.25 1.25 0 0 0 1.46 1.46l3.39-1.15A9.4 9.4 0 0 0 10 17.5c4.97 0 9-3.58 9-8s-4.03-8-9-8Z" />
      </svg>
    ),
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: (
      <svg className="NavTabs__ItemIcon" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
        <path d="M8.59 1.44a1.5 1.5 0 0 1 2.82 0l.47 1.33a1.5 1.5 0 0 0 1.78.9l1.37-.36a1.5 1.5 0 0 1 1.41 2.44l-.9.97a1.5 1.5 0 0 0 0 2.04l.9.97a1.5 1.5 0 0 1-1.41 2.44l-1.37-.36a1.5 1.5 0 0 0-1.78.9l-.47 1.33a1.5 1.5 0 0 1-2.82 0l-.47-1.33a1.5 1.5 0 0 0-1.78-.9l-1.37.36a1.5 1.5 0 0 1-1.41-2.44l.9-.97a1.5 1.5 0 0 0 0-2.04l-.9-.97A1.5 1.5 0 0 1 4.97 3.3l1.37.36a1.5 1.5 0 0 0 1.78-.9l.47-1.33ZM10 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" />
      </svg>
    ),
  },
];

export function NavTabs() {
  const activeTab = useStore((s) => s.activeTab);
  const setActiveTab = useStore((s) => s.setActiveTab);

  return (
    <nav className="NavTabs" aria-label="Main navigation">
      <div className="NavTabs__TabList">
        {TABS.map((tab) => (
          <div key={tab.id} className="NavTabs__Item">
            <button
              type="button"
              className={`NavTabs__ItemButton ${activeTab === tab.id ? 'NavTabs__ItemButton--active' : ''}`}
              aria-label={tab.label}
              aria-current={activeTab === tab.id ? 'page' : undefined}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.icon}
            </button>
          </div>
        ))}
      </div>
    </nav>
  );
}
