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
  | {
      step: 'LOGIN';
      context: OAuthTransactionContext;
      error?: string;
      requireMfa?: boolean;
    }
  | {
      step: 'SIGNUP';
      context: OAuthTransactionContext;
      error?: string;
    }
  | {
      step: 'FORGOT_PASSWORD';
      context: OAuthTransactionContext;
      error?: string;
    }
  | {
      step: 'CONSENT';
      context: OAuthTransactionContext;
      credentials: {
        email: string;
        password?: string;
        otpCode?: string;
        passkeyCredentialId?: string;
        mfaCode?: string;
        useSsoCookie?: boolean;
      };
      error?: string;
    }
  | { step: 'DEV_PORTAL'; context?: OAuthTransactionContext }
  | { step: 'REDIRECTING'; redirectTo: string };
