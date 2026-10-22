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
}

/**
 * Creates Clerk-like React components and hooks (`<SoAuthProvider>`, `useSoAuth`, `<SignInButton>`, `<UserButton>`, `<SignedIn>`, `<SignedOut>`).
 *
 * Example:
 * ```tsx
 * import React from 'react';
 * import { createSoAuthReact } from '@soauth/sdk/react';
 *
 * export const {
 *   SoAuthProvider,
 *   useSoAuth,
 *   SignedIn,
 *   SignedOut,
 *   SignInButton,
 *   UserButton,
 * } = createSoAuthReact(React);
 * ```
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
          background: '#0284c7',
          color: '#ffffff',
          border: 'none',
          padding: '0.6rem 1.15rem',
          borderRadius: '6px',
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
            background: '#0284c7',
            color: '#ffffff',
            border: '2px solid #e0f2fe',
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
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                padding: '0.85rem',
                minWidth: '220px',
                boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1)',
                zIndex: 50,
              },
            },
            React.createElement(
              'div',
              {
                style: {
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#0f172a',
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
                  color: '#16a34a',
                  marginBottom: '0.75rem',
                },
              },
              '✓ Verified soauth Identity',
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => void logout(props.afterSignOutUrl),
                style: {
                  width: '100%',
                  background: '#fee2e2',
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

  return {
    SoAuthProvider,
    useSoAuth,
    SignedIn,
    SignedOut,
    SignInButton,
    UserButton,
  };
}
