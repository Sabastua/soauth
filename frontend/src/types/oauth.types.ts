export interface OAuthTransactionContext {
  clientId: string;
  appName: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
}

export type AuthFlowStep =
  | { step: 'LOGIN'; context: OAuthTransactionContext; error?: string }
  | {
      step: 'CONSENT';
      context: OAuthTransactionContext;
      credentials: { email: string; password: string };
      error?: string;
    }
  | { step: 'REDIRECTING'; redirectTo: string };
