// Server-side shapes (after camelize) and decrypted "views". Everything optional on the raw
// side: Vaultwarden omits/nulls fields freely, and older items lack newer fields.

export const CipherType = { Login: 1, SecureNote: 2, Card: 3, Identity: 4, SshKey: 5 } as const;
export type CipherType = (typeof CipherType)[keyof typeof CipherType];

export const UriMatch = { Domain: 0, Host: 1, StartsWith: 2, Exact: 3, RegularExpression: 4, Never: 5 } as const;
export type UriMatch = (typeof UriMatch)[keyof typeof UriMatch];

export const FieldType = { Text: 0, Hidden: 1, Boolean: 2, Linked: 3 } as const;
export type FieldType = (typeof FieldType)[keyof typeof FieldType];

export const RepromptType = { None: 0, Password: 1 } as const;

export interface RawUri {
  uri?: string | null;
  uriChecksum?: string | null;
  match?: number | null;
}
export interface RawFido2 {
  credentialId?: string;
  keyType?: string;
  keyAlgorithm?: string;
  keyCurve?: string;
  keyValue?: string;
  rpId?: string;
  userHandle?: string | null;
  userName?: string | null;
  counter?: string;
  rpName?: string | null;
  userDisplayName?: string | null;
  discoverable?: string;
  creationDate?: string;
}
export interface RawLogin {
  uris?: RawUri[] | null;
  username?: string | null;
  password?: string | null;
  passwordRevisionDate?: string | null;
  totp?: string | null;
  autofillOnPageLoad?: boolean | null;
  fido2Credentials?: RawFido2[] | null;
}
export interface RawField {
  type?: number;
  name?: string | null;
  value?: string | null;
  linkedId?: number | null;
}
export interface RawAttachment {
  id: string;
  url?: string | null;
  fileName?: string | null;
  key?: string | null;
  size?: string | number | null;
  sizeName?: string | null;
}
export interface RawCipher {
  id: string;
  type: number;
  name?: string | null;
  notes?: string | null;
  key?: string | null;
  favorite?: boolean;
  folderId?: string | null;
  organizationId?: string | null;
  collectionIds?: string[] | null;
  reprompt?: number | null;
  creationDate?: string | null;
  revisionDate?: string | null;
  deletedDate?: string | null;
  archivedDate?: string | null;
  edit?: boolean;
  viewPassword?: boolean;
  organizationUseTotp?: boolean;
  permissions?: { delete?: boolean; restore?: boolean } | null;
  login?: RawLogin | null;
  card?: Record<string, string | null> | null;
  identity?: Record<string, string | null> | null;
  secureNote?: { type?: number } | null;
  sshKey?: { privateKey?: string | null; publicKey?: string | null; keyFingerprint?: string | null } | null;
  fields?: RawField[] | null;
  passwordHistory?: { password?: string; lastUsedDate?: string }[] | null;
  attachments?: RawAttachment[] | null;
  [k: string]: unknown;
}
export interface RawFolder {
  id: string;
  name: string;
  revisionDate?: string;
}
export interface RawCollection {
  id: string;
  organizationId: string;
  name: string;
  readOnly?: boolean;
  hidePasswords?: boolean;
  manage?: boolean;
}
export interface RawOrg {
  id: string;
  name: string;
  key?: string;
  enabled?: boolean;
  status?: number;
  type?: number;
  useTotp?: boolean;
}

// ---- decrypted views ----

export interface UriView {
  uri: string;
  match: UriMatch | null;
}
export interface Fido2View {
  credentialId: string;
  keyType: string;
  keyAlgorithm: string;
  keyCurve: string;
  keyValue: string;
  rpId: string;
  userHandle: string | null;
  userName: string | null;
  counter: number;
  rpName: string | null;
  userDisplayName: string | null;
  discoverable: boolean;
  creationDate: string;
}
export interface LoginView {
  username: string | null;
  password: string | null;
  passwordRevisionDate: string | null;
  totp: string | null;
  uris: UriView[];
  autofillOnPageLoad: boolean | null;
  fido2Credentials: Fido2View[];
}
export interface CardView {
  cardholderName: string | null;
  brand: string | null;
  number: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
}
export const IDENTITY_FIELDS = [
  "title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state", "postalCode",
  "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber",
] as const;
export type IdentityView = Record<(typeof IDENTITY_FIELDS)[number], string | null>;
export const CARD_FIELDS = ["cardholderName", "brand", "number", "expMonth", "expYear", "code"] as const;
export interface SshKeyView {
  privateKey: string | null;
  publicKey: string | null;
  keyFingerprint: string | null;
}
export interface FieldView {
  type: FieldType;
  name: string | null;
  value: string | null;
  linkedId: number | null;
}
export interface PasswordHistoryView {
  password: string;
  lastUsedDate: string;
}
export interface AttachmentView {
  id: string;
  fileName: string | null;
  size: number;
  sizeName: string | null;
  url: string | null;
  key: string | null; // still encrypted (wrapped by the item key); unwrapped at download time
}
export interface CipherView {
  id: string;
  type: CipherType;
  name: string;
  notes: string | null;
  favorite: boolean;
  reprompt: number;
  folderId: string | null;
  organizationId: string | null;
  collectionIds: string[];
  creationDate: string | null;
  revisionDate: string | null;
  deletedDate: string | null;
  archivedDate: string | null;
  edit: boolean;
  viewPassword: boolean;
  login: LoginView | null;
  card: CardView | null;
  identity: IdentityView | null;
  sshKey: SshKeyView | null;
  fields: FieldView[];
  passwordHistory: PasswordHistoryView[];
  attachments: AttachmentView[];
  /** fields that failed to decrypt; the item still opens */
  errors: string[];
  /** whether the item uses its own (cipher) key */
  hasItemKey: boolean;
}

/** Compact, list-ready subset of an item. Sealed into the local cache; no secrets beyond URIs/usernames. */
export interface Summary {
  id: string;
  type: CipherType;
  name: string;
  sub: string;
  fav: boolean;
  folder: string | null;
  org: string | null;
  cols: string[];
  uris: string[];
  match: (number | null)[];
  totp: boolean;
  pk: string[]; // passkey rpIds
  rp: boolean; // reprompt
  att: boolean;
  del: string | null;
  arch: string | null;
  rev: string | null;
  created: string | null;
  pwRev: string | null;
  note: string | null; // first 160 chars of notes, for search
  brand: string | null;
  err: string | null;
}
