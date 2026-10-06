export type ScannerErrorCode =
  | 'SCAN_ABORTED'
  | 'INVALID_FILE_PATH'
  | 'FILE_NOT_ELIGIBLE'
  | 'REPOSITORY_ACCESS_FAILED'
  | 'INVALID_FINDING'
  | 'INVALID_PACK'
  | 'DUPLICATE_PACK_ID'
  | 'DUPLICATE_RULE_ID'
  | 'UNKNOWN_PACK'
  | 'INVALID_SCAN_OPTIONS'
  | 'INVALID_SCAN_TARGET'
  | 'RULE_EXECUTION_FAILED';

export interface ScannerErrorDetails {
  packId?: string;
  ruleId?: string;
}

export class ScannerError extends Error {
  readonly code: ScannerErrorCode;
  readonly packId?: string;
  readonly ruleId?: string;

  constructor(code: ScannerErrorCode, message: string, details: ScannerErrorDetails = {}) {
    super(message);
    this.name = 'ScannerError';
    this.code = code;
    if (details.packId !== undefined) this.packId = details.packId;
    if (details.ruleId !== undefined) this.ruleId = details.ruleId;
  }
}
