<script setup lang="ts">
import sodium from "libsodium-wrappers-sumo";
import { computed, onMounted, ref, watch } from "vue";

type StoredNote = {
  payload: string | null;
  updatedAt: string | null;
};

type LegacyEncryptedPayload = {
  v: 1;
  kdf: "PBKDF2-SHA256";
  cipher: "AES-GCM";
  iterations: number;
  salt: string;
  iv: string;
  data: string;
};

type EncryptedPayload = {
  v: 2;
  kdf: "libsodium-crypto_pwhash";
  cipher: "xchacha20poly1305";
  opslimit: number;
  memlimit: number;
  salt: string;
  nonce: string;
  data: string;
};

const apiBase = import.meta.env.VITE_API_BASE ?? "";
const rememberedPasswordKey = "cloud-notes:remembered-password";

const password = ref("");
const rememberPassword = ref(false);
const note = ref("");
const updatedAt = ref<string | null>(null);
const isUnlocked = ref(false);
const isLoading = ref(false);
const isSaving = ref(false);
const status = ref("输入密码后读取便签");
const errorMessage = ref("");

const updatedAtText = computed(() => {
  if (!updatedAt.value) {
    return "尚未保存";
  }

  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(updatedAt.value));
});

onMounted(() => {
  const rememberedPassword = localStorage.getItem(rememberedPasswordKey);
  if (rememberedPassword) {
    password.value = rememberedPassword;
    rememberPassword.value = true;
    status.value = "已填入保存的密码";
  }
});

watch(rememberPassword, (shouldRemember) => {
  if (!shouldRemember) {
    localStorage.removeItem(rememberedPasswordKey);
    return;
  }

  if (password.value) {
    localStorage.setItem(rememberedPasswordKey, password.value);
  }
});

watch(password, (nextPassword) => {
  if (rememberPassword.value && nextPassword) {
    localStorage.setItem(rememberedPasswordKey, nextPassword);
  }
});

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function deriveLegacyKey(
  passwordText: string,
  salt: BufferSource,
  iterations: number
) {
  if (!crypto.subtle) {
    throw new Error("旧密文需要 HTTPS 环境读取");
  }

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passwordText),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptNote(plainText: string, passwordText: string): Promise<string> {
  await sodium.ready;

  const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const key = sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passwordText,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plainText,
    null,
    null,
    nonce,
    key
  );
  const payload: EncryptedPayload = {
    v: 2,
    kdf: "libsodium-crypto_pwhash",
    cipher: "xchacha20poly1305",
    opslimit,
    memlimit,
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(nonce),
    data: bytesToBase64(encrypted)
  };

  return JSON.stringify(payload);
}

async function decryptNote(payloadText: string, passwordText: string): Promise<string> {
  const payload = JSON.parse(payloadText) as Partial<
    EncryptedPayload | LegacyEncryptedPayload
  >;

  if (payload.v === 1) {
    return decryptLegacyNote(payload, passwordText);
  }

  if (
    payload.v !== 2 ||
    payload.kdf !== "libsodium-crypto_pwhash" ||
    payload.cipher !== "xchacha20poly1305" ||
    typeof payload.opslimit !== "number" ||
    typeof payload.memlimit !== "number" ||
    typeof payload.salt !== "string" ||
    typeof payload.nonce !== "string" ||
    typeof payload.data !== "string"
  ) {
    throw new Error("密文格式不正确");
  }

  await sodium.ready;

  const salt = base64ToBytes(payload.salt);
  const nonce = base64ToBytes(payload.nonce);
  const ciphertext = base64ToBytes(payload.data);
  const key = sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passwordText,
    salt,
    payload.opslimit,
    payload.memlimit,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    key,
    "text"
  );

  return decrypted;
}

async function decryptLegacyNote(
  payload: Partial<LegacyEncryptedPayload>,
  passwordText: string
): Promise<string> {
  if (
    payload.v !== 1 ||
    payload.kdf !== "PBKDF2-SHA256" ||
    payload.cipher !== "AES-GCM" ||
    typeof payload.iterations !== "number" ||
    typeof payload.salt !== "string" ||
    typeof payload.iv !== "string" ||
    typeof payload.data !== "string"
  ) {
    throw new Error("密文格式不正确");
  }

  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.data);
  const key = await deriveLegacyKey(passwordText, salt, payload.iterations);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);

  return new TextDecoder().decode(decrypted);
}

async function fetchNote(): Promise<StoredNote> {
  const response = await fetch(`${apiBase}/api/note`);
  if (!response.ok) {
    throw new Error("读取失败");
  }
  return response.json() as Promise<StoredNote>;
}

async function unlock() {
  if (!password.value) {
    errorMessage.value = "请输入密码";
    return;
  }

  isLoading.value = true;
  errorMessage.value = "";
  status.value = "正在读取";

  try {
    const stored = await fetchNote();
    updatedAt.value = stored.updatedAt;

    if (!stored.payload) {
      note.value = "";
      isUnlocked.value = true;
      syncRememberedPassword();
      status.value = "新便签";
      return;
    }

    note.value = await decryptNote(stored.payload, password.value);
    isUnlocked.value = true;
    syncRememberedPassword();
    status.value = "已解锁";
  } catch (error) {
    isUnlocked.value = false;
    note.value = "";
    errorMessage.value =
      error instanceof Error ? error.message : "密码错误或服务不可用";
    status.value = "解锁失败";
  } finally {
    isLoading.value = false;
  }
}

async function save() {
  if (!password.value) {
    errorMessage.value = "请输入密码";
    return;
  }

  isSaving.value = true;
  errorMessage.value = "";
  status.value = "正在加密保存";

  try {
    const payload = await encryptNote(note.value, password.value);
    const response = await fetch(`${apiBase}/api/note`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ payload })
    });

    if (!response.ok) {
      throw new Error("保存失败");
    }

    const stored = (await response.json()) as StoredNote;
    updatedAt.value = stored.updatedAt;
    isUnlocked.value = true;
    syncRememberedPassword();
    status.value = "已保存";
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : "保存失败";
    status.value = "保存失败";
  } finally {
    isSaving.value = false;
  }
}

function lock() {
  note.value = "";
  if (!rememberPassword.value) {
    password.value = "";
  }
  updatedAt.value = null;
  isUnlocked.value = false;
  errorMessage.value = "";
  status.value = "已锁定";
}

function syncRememberedPassword() {
  if (rememberPassword.value && password.value) {
    localStorage.setItem(rememberedPasswordKey, password.value);
    return;
  }

  localStorage.removeItem(rememberedPasswordKey);
}
</script>

<template>
  <main class="shell">
    <section class="panel">
      <header class="header">
        <div>
          <p class="eyebrow">Client-side encrypted</p>
          <h1>加密云便签</h1>
        </div>
        <span class="status">{{ status }}</span>
      </header>

      <form class="unlock-bar" @submit.prevent="unlock">
        <input
          v-model="password"
          autocomplete="current-password"
          class="password-input"
          placeholder="输入密码"
          type="password"
        />
        <button :disabled="isLoading" type="submit">
          {{ isLoading ? "读取中" : "读取" }}
        </button>
        <button :disabled="!isUnlocked" type="button" class="secondary" @click="lock">
          锁定
        </button>
      </form>

      <label class="remember-row">
        <input v-model="rememberPassword" type="checkbox" />
        <span>在此浏览器记住密码</span>
      </label>

      <p v-if="errorMessage" class="error">{{ errorMessage }}</p>

      <textarea
        v-model="note"
        :disabled="!isUnlocked"
        class="note-editor"
        placeholder="解锁后编辑便签"
        spellcheck="false"
      />

      <footer class="actions">
        <span>最后保存：{{ updatedAtText }}</span>
        <button :disabled="!isUnlocked || isSaving" type="button" @click="save">
          {{ isSaving ? "保存中" : "加密保存" }}
        </button>
      </footer>
    </section>
  </main>
</template>
