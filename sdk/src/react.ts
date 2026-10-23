import { SoAuthClient, type SoAuthClientConfig, type SoAuthState } from './index.js';

/**
 * Minimal structural interface for React 18/19 to avoid hard peer dependency issues during build.
 */
export interface ReactLike {
  createElement(type: unknown, props?: Record<string, unknown> | null, ...children: unknown[]): unknown;
  createContext<T>(defaultValue: T): {
    Provider: unknown;
    Consumer: unknown;
  };
  useContext<T>(context: { Provider: unknown }): T;
  useState<S>(initialState: S | (() => S)): [S, (newState: S) => void];
  useEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void;
  useMemo<T>(factory: () => T, deps: readonly unknown[]): T;
}

export interface SoAuthContextValue extends SoAuthState {
  loginWithRedirect: (customScope?: string) => Promise<void>;
  logout: (postLogoutRedirectUri?: string) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  hasRole: (expectedRole: string) => boolean;
  hasOrgRole: (expectedOrgRole: string) => boolean;
}

/**
 * Creates Clerk-like React components and hooks (`<SoAuthProvider>`, `useSoAuth`, `<SignInButton>`, `<UserButton>`, `<OrganizationSwitcher>`, `<UserProfile>`, `<SignedIn>`, `<SignedOut>`).
 */
export function createSoAuthReact(React: ReactLike) {
  const SoAuthContext = React.createContext<SoAuthContextValue | null>(null);

  function SoAuthProvider(props: SoAuthClientConfig & { children?: unknown }) {
    const client = React.useMemo(
      () =>
        new SoAuthClient({
          issuerUrl: props.issuerUrl,
          clientId: props.clientId,
          ...(props.clientSecret ? { clientSecret: props.clientSecret } : {}),
          ...(props.redirectUri ? { redirectUri: props.redirectUri } : {}),
          ...(props.scope ? { scope: props.scope } : {}),
        }),
      [props.issuerUrl, props.clientId, props.clientSecret, props.redirectUri, props.scope],
    );

    const [state, setState] = React.useState<SoAuthState>(() => client.getState());

    React.useEffect(() => {
      const unsubscribe = client.subscribe((nextState) => {
        setState(nextState);
      });
      void client.initialize();
      return unsubscribe;
    }, [client]);

    const contextValue = React.useMemo<SoAuthContextValue>(
      () => ({
        ...state,
        loginWithRedirect: (scope?: string) => client.loginWithRedirect(scope),
        logout: (postLogoutRedirectUri?: string) => client.logout(postLogoutRedirectUri),
        getAccessToken: () => client.getAccessToken(),
        hasRole: (expectedRole: string) => client.hasRole(expectedRole),
        hasOrgRole: (expectedOrgRole: string) => client.hasOrgRole(expectedOrgRole),
      }),
      [state, client],
    );

    return React.createElement(
      SoAuthContext.Provider,
      { value: contextValue },
      props.children,
    );
  }

  function useSoAuth(): SoAuthContextValue {
    const ctx = React.useContext<SoAuthContextValue | null>(SoAuthContext);
    if (!ctx) {
      throw new Error('useSoAuth() must be used inside a <SoAuthProvider>');
    }
    return ctx;
  }

  function SignedIn(props: { children?: unknown }) {
    const { isAuthenticated, isLoading } = useSoAuth();
    if (isLoading || !isAuthenticated) return null;
    return React.createElement('div', { style: { display: 'contents' } }, props.children);
  }

  function SignedOut(props: { children?: unknown }) {
    const { isAuthenticated, isLoading } = useSoAuth();
    if (isLoading || isAuthenticated) return null;
    return React.createElement('div', { style: { display: 'contents' } }, props.children);
  }

  function SignInButton(props: { label?: string; scope?: string; style?: Record<string, unknown> }) {
    const { loginWithRedirect, isAuthenticated } = useSoAuth();
    if (isAuthenticated) return null;

    return React.createElement(
      'button',
      {
        type: 'button',
        onClick: () => void loginWithRedirect(props.scope),
        style: {
          background: '#ffffff',
          color: '#111827',
          border: '1.5px solid #111827',
          padding: '0.6rem 1.15rem',
          borderRadius: '8px',
          fontWeight: 600,
          fontSize: '0.9rem',
          cursor: 'pointer',
          ...(props.style ?? {}),
        },
      },
      props.label ?? 'Sign in with soauth',
    );
  }

  function UserButton(props: { afterSignOutUrl?: string }) {
    const { user, isAuthenticated, logout } = useSoAuth();
    const [open, setOpen] = React.useState(false);

    if (!isAuthenticated || !user) return null;
    const initial = (user.email ?? user.sub ?? 'U').charAt(0).toUpperCase();

    return React.createElement(
      'div',
      { style: { position: 'relative', display: 'inline-block' } },
      React.createElement(
        'button',
        {
          type: 'button',
          onClick: () => setOpen(!open),
          title: user.email ?? user.sub,
          style: {
            width: '38px',
            height: '38px',
            borderRadius: '50%',
            background: '#ffffff',
            color: '#111827',
            border: '1.5px solid #111827',
            fontWeight: 700,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          },
        },
        initial,
      ),
      open
        ? React.createElement(
            'div',
            {
              style: {
                position: 'absolute',
                right: 0,
                marginTop: '0.5rem',
                background: '#ffffff',
                border: '1px solid #e5e7eb',
                borderRadius: '10px',
                padding: '0.9rem',
                minWidth: '230px',
                boxShadow: '0 10px 15px -3px rgba(0,0,0,0.06)',
                zIndex: 50,
              },
            },
            React.createElement(
              'div',
              {
                style: {
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#111827',
                  marginBottom: '0.2rem',
                  wordBreak: 'break-all',
                },
              },
              user.email ?? user.sub,
            ),
            React.createElement(
              'div',
              {
                style: {
                  fontSize: '0.72rem',
                  color: '#4b5563',
                  marginBottom: '0.75rem',
                },
              },
              `Verified Identity (${user.org_slug ?? user.role ?? 'member'})`,
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => void logout(props.afterSignOutUrl),
                style: {
                  width: '100%',
                  background: '#ffffff',
                  color: '#991b1b',
                  border: '1px solid #fca5a5',
                  padding: '0.45rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                },
              },
              'Sign out',
            ),
          )
        : null,
    );
  }

  /**
   * Feature 2: <OrganizationSwitcher /> drop-in React component for switching B2B tenant workspaces.
   */
  function OrganizationSwitcher(props: {
    organizations?: Array<{ id: string; name: string; slug: string }>;
    activeOrgId?: string;
    onSwitchOrganization?: (orgId: string) => void;
  }) {
    const { user } = useSoAuth();
    const currentSlug = user?.org_slug ?? 'acme-corp';
    const currentRole = user?.org_role ?? 'org:admin';
    const orgs = props.organizations ?? [
      { id: user?.org_id ?? 'org_default', name: currentSlug, slug: currentSlug },
    ];

    return React.createElement(
      'div',
      {
        style: {
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          background: '#ffffff',
          border: '1px solid #e5e7eb',
          borderRadius: '8px',
          padding: '0.35rem 0.65rem',
        },
      },
      React.createElement(
        'span',
        {
          style: {
            fontSize: '0.75rem',
            fontWeight: 700,
            color: '#111827',
          },
        },
        'ORG:',
      ),
      React.createElement(
        'select',
        {
          value: props.activeOrgId ?? user?.org_id ?? orgs[0]?.id,
          onChange: (e: { target: { value: string } }) =>
            props.onSwitchOrganization?.(e.target.value),
          style: {
            background: '#ffffff',
            color: '#111827',
            border: 'none',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            outline: 'none',
          },
        },
        ...orgs.map((o) =>
          React.createElement('option', { key: o.id, value: o.id }, `${o.name} (${currentRole})`),
        ),
      ),
    );
  }

  /**
   * Feature 5: <UserProfile /> Self-Service End-User Account Management Widget.
   */
  function UserProfile() {
    const { user, logout } = useSoAuth();
    if (!user) return null;

    return React.createElement(
      'div',
      {
        style: {
          background: '#ffffff',
          border: '1px solid #e5e7eb',
          borderRadius: '12px',
          padding: '1.5rem',
          color: '#111827',
          maxWidth: '560px',
        },
      },
      React.createElement(
        'h3',
        { style: { margin: '0 0 0.35rem 0', fontSize: '1.1rem', fontWeight: 700 } },
        'Account Security & Profile',
      ),
      React.createElement(
        'p',
        { style: { margin: '0 0 1rem 0', fontSize: '0.84rem', color: '#4b5563' } },
        `Signed in as ${user.email ?? user.sub} | Role: ${user.role ?? 'member'} | Org: ${user.org_slug ?? 'personal'}`,
      ),
      React.createElement(
        'button',
        {
          type: 'button',
          onClick: () => void logout(),
          style: {
            background: '#ffffff',
            color: '#111827',
            border: '1px solid #111827',
            borderRadius: '8px',
            padding: '0.5rem 1rem',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
          },
        },
        'Sign out of current session',
      ),
    );
  }

  return {
    SoAuthProvider,
    useSoAuth,
    SignedIn,
    SignedOut,
    SignInButton,
    UserButton,
    OrganizationSwitcher,
    UserProfile,
  };
}
