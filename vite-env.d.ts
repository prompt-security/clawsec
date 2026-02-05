/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_CLAWSEC_SUITE_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
