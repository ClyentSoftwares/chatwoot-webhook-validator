export interface ValidatorOptions {
  maxAge?: number;
  signatureHeader?: string;
  timestampHeader?: string;
}

export interface ValidationResult {
  isValid: boolean;
  error?: string;
}

export type ChatwootWebhookValidatorOptions = ValidatorOptions & {
  hmacToken: string;
};
