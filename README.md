# MR-KING PHANTOM — FastAPI Backend v2.1

Firebase-Authenticated, server-side **AES-256-GCM** envelope encryption API।
Render पर deploy करने योग्य, GitHub private repo के साथ सुरक्षित, और HTML/CSS/JS frontend के साथ आसानी से integrate होने योग्य।

- **Backend:** Python 3.10+ / FastAPI / Uvicorn
- **Auth:** Firebase Admin SDK (ID token verification)
- **Cipher:** AES-256-GCM, per-request random 256-bit DEK, अलग IVs
- **Key management:** Versioned master keys (KEK) → भविष्य में rotation possible
- **Firebase Project ID:** `encryption-ee299`
- **Hosting:** Render
- **Frontend:** HTML + CSS + JavaScript (Firebase client SDK)

---

## 1. Security Model (सारांश)

**Encryption:**
1. हर request पर नया random **256-bit DEK** बनता है।
2. Plaintext → DEK से **AES-256-GCM** encrypt (नया 12-byte `dataIv`)।
3. DEK → server **KEK** से wrap (नया 12-byte `wrappedKeyIv`)।
4. AAD में `ownerUid`, `keyVersion`, और format version bind होते हैं।
5. Payload में: `ownerUid`, IVs, wrapped key, ciphertext, authTag।

**Decryption:**
1. Firebase ID token verify → UID निकाला जाता है।
2. `payload.ownerUid == token.uid` check → mismatch पर **403**।
3. KEK से DEK unwrap, फिर AES-GCM authentication tag verify।
4. Tampered / modified payload → **400** (GCM authentication failure)।
5. Success पर: `{"plaintext": "...", "ownerUid": "..."}`।

**महत्वपूर्ण:**
- Firebase UID **हमेशा verified token से** लिया जाता है, कभी client body से नहीं।
- Master key, tokens, plaintext कभी log नहीं होते।
- Error messages में कोई cryptographic detail नहीं।

---

## 2. API Endpoints

### `GET /health` (public, no auth)
```bash
curl https://<your-service>.onrender.com/health
```
Response:
```json
{"status":"ok","service":"MR-KING PHANTOM","version":2,"keyVersion":1,"time":1735000000}
```

### `POST /v1/encrypt`
`Authorization: Bearer <FIREBASE_ID_TOKEN>` ज़रूरी।

Request:
```json
{ "plaintext": "My secret data" }
```

Response:
```json
{
  "payload": {
    "format": "MRK-PHANTOM-SERVER",
    "version": 2,
    "cipher": "AES-256-GCM",
    "keyMode": "SERVER_WRAPPED_DATA_KEY",
    "ownerUid": "FIREBASE_UID",
    "keyVersion": 1,
    "dataIv": "base64...",
    "wrappedKeyIv": "base64...",
    "wrappedKey": "base64...",
    "ciphertext": "base64...",
    "authTag": "base64...",
    "createdAt": 1735000000
  }
}
```

### `POST /v1/decrypt`
Request:
```json
{ "payload": { ...ऊपर मिला पूरा object, वैसा ही... } }
```
Response:
```json
{ "plaintext": "My secret data", "ownerUid": "FIREBASE_UID" }
```

### `POST /v1/decrypt/legacy` (पुराने snake_case payloads के लिए)
Request:
```json
{ "envelope": { "format": "...", "version": 2, "cipher": "...",
                "key_mode": "...", "owner_uid": "...",
                "ciphertext_iv": "...", "ciphertext_ct": "...",
                "wrapped_key_iv": "...", "wrapped_key_ct": "..." } }
```

### Error Codes
| Status | अर्थ |
|---|---|
| 400 | Malformed / tampered / unsupported payload |
| 401 | Firebase token गायब / invalid / expired / revoked |
| 403 | Payload किसी और Firebase account का है |
| 413 | Plaintext > 2 MiB या envelope > 4 MiB |
| 422 | Request schema invalid |
| 429 | Rate limit exceed (`Retry-After` header मिलेगा) |
| 500 | Server error (details leak नहीं) |

---

## 3. फ़ाइलें (Project Structure)

```
.
├── main.py             # पूरा FastAPI backend
├── requirements.txt    # Python dependencies
├── .gitignore          # secrets Git से बाहर रखने के लिए
├── .env.example        # env variables template
├── README.md           # यह फ़ाइल
└── test_main.py        # optional automated tests
```

---

## 4. Master Key बनाना

अपने computer पर एक बार चलाएँ:

```bash
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Output (लंबा base64 string) **दो जगह** सुरक्षित रखें:
1. **Password manager** (जैसे Bitwarden, 1Password)।
2. **Render Environment variable** `MRK_MASTER_KEY_B64` में।

⚠️ **कभी भी इस key को:**
- GitHub में commit न करें
- frontend HTML/JS में न रखें
- WhatsApp/Email/chat में share न करें (कम से कम public chats में)
- किसी AI को न भेजें

**Key खोने पर उस version के सारे payloads हमेशा के लिए decrypt नहीं होंगे।**

---

## 5. Firebase Service Account JSON

1. Firebase Console → अपना project **`encryption-ee299`** खोलें।
2. ⚙️ **Project settings** → **Service accounts** tab।
3. **Generate new private key** → JSON file download होगी।
4. JSON को text editor में खोलें।
5. **पूरा JSON एक ही line में** copy करें (या online "JSON minify" करें)।
6. इसे Render के env var `FIREBASE_SERVICE_ACCOUNT_JSON` में paste करें।
7. **इस file को कभी GitHub पर push न करें।**

---

## 6. GitHub पर Private Repository

### 6.1 Repo बनाना
1. https://github.com/new खोलें।
2. **Repository name:** `mr-king-phantom-backend`
3. **Visibility:** **Private**
4. कोई भी "Initialize" option tick न करें।
5. **Create repository** दबाएँ।

### 6.2 Files upload करना (ZIP extract के बाद)
1. अपने computer पर ZIP extract करें — 6 files मिलेंगी।
2. Repo page → **Add file** → **Upload files**।
3. सारी files drag-and-drop करें।
   - Linux/Mac: dotfiles देखने के लिए `Ctrl+H`।
   - Windows: File Explorer → View → Show → Hidden items।
4. Commit message: `Initial backend v2.1`
5. **Commit changes** दबाएँ।

### 6.3 Secrets check (push से पहले)
- `.env` file repo में **नहीं** होनी चाहिए
- कोई `*service-account*.json` **नहीं** होनी चाहिए
- `.gitignore` मौजूद है

Commit करने से पहले (local git): `git status` चलाएँ — कहीं भी `.env` या service-account JSON दिखे तो remove करें।

---

## 7. Render पर Deploy करना

### 7.1 Web Service बनाना
1. https://dashboard.render.com/ → GitHub से sign in।
2. **New +** → **Web Service**।
3. **Connect a repository** → अपनी `mr-king-phantom-backend` चुनें।

### 7.2 Settings

| Field | Value |
|---|---|
| **Name** | `mr-king-phantom` |
| **Region** | Singapore (भारत के लिए नज़दीक) |
| **Branch** | `main` |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| **Instance Type** | Free (शुरुआत के लिए) |

### 7.3 Environment Variables (Render → Environment)

| Key | Value |
|---|---|
| `ENV` | `production` |
| `MRK_MASTER_KEY_B64` | (Section 4 से generate किया base64) |
| `MRK_MASTER_KEY_VERSION` | `1` |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | (Section 5 का single-line JSON) |
| `FIREBASE_PROJECT_ID` | `encryption-ee299` |
| `ALLOWED_ORIGINS` | अपना frontend HTTPS origin, जैसे `https://mrkingphantom.example.com` |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` (optional) |
| `RATE_LIMIT_ENCRYPT` | `30` (optional) |
| `RATE_LIMIT_DECRYPT` | `60` (optional) |

**Create Web Service** दबाएँ। Render automatically build और deploy करेगा।

### 7.4 Health Check Test
```bash
curl https://<your-service>.onrender.com/health
# → {"status":"ok","service":"MR-KING PHANTOM","version":2,"keyVersion":1,...}
```

### 7.5 Encryption Test
Firebase ID token लें (frontend से `getIdToken()`), फिर:
```bash
ID_TOKEN="<paste-firebase-id-token>"

curl -X POST https://<your-service>.onrender.com/v1/encrypt \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"Hello Phantom"}'
```

Response के `payload` object को copy करें, फिर decrypt test:
```bash
curl -X POST https://<your-service>.onrender.com/v1/decrypt \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payload": { ...copy किया object... }}'
```

---

## 8. Frontend Integration (Firebase Modular SDK v9+)

### 8.1 HTML में Firebase config
**अपनी वास्तविक Firebase Web Config** को नीचे रखें (यह public है, यही designed है frontend के लिए):

```html
<script type="module">
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.13.0/firebase-app.js";
import {
  getAuth, signInWithEmailAndPassword, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.13.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCermMUMV3QfyfIlVmeXYi-VbDb6QWajGw",
  authDomain: "encryption-ee299.firebaseapp.com",
  databaseURL: "https://encryption-ee299-default-rtdb.firebaseio.com",
  projectId: "encryption-ee299",
  storageBucket: "encryption-ee299.firebasestorage.app",
  messagingSenderId: "566306955664",
  appId: "1:566306955664:web:8e784060131e6fecb49315",
  measurementId: "G-PRB58G90CC"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const API_BASE = "https://<your-service>.onrender.com";

async function getToken(force = true) {
  const user = auth.currentUser;
  if (!user) throw new Error("Not signed in");
  return await user.getIdToken(force);
}

async function encryptData(plaintext) {
  const token = await getToken();
  const res = await fetch(`${API_BASE}/v1/encrypt`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify({ plaintext })
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.error || `Encrypt failed (${res.status})`);
  }
  const data = await res.json();
  return data.payload;   // ← यही JSON Phone B पर भेजें
}

async function decryptData(payload) {
  const token = await getToken();
  const res = await fetch(`${API_BASE}/v1/decrypt`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify({ payload })
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.error || `Decrypt failed (${res.status})`);
  }
  const data = await res.json();
  return data.plaintext;
}

// Login example
async function login(email, password) {
  await signInWithEmailAndPassword(auth, email, password);
}
</script>
```

### 8.2 Cross-Device Flow (Phone A → Phone B)
1. **Phone A:** same Firebase account से login → `encryptData("secret")` → payload object मिलेगा।
2. Payload object को **download / copy / QR / cloud** के ज़रिए Phone B तक पहुँचाएँ।
3. **Phone B:** **उसी Firebase account** से login → `decryptData(payload)` → plaintext मिलेगा।
4. दूसरे Firebase account से कोशिश करें → backend **403** return करेगा।

**ध्यान:** यह account-based authorization है, file-based नहीं। Authorized user plaintext की copy बना सकता है — backend इसे रोक नहीं सकता।

---

## 9. Key Rotation (भविष्य के लिए)

मान लीजिए आप key बदलना चाहते हैं:

1. नई key generate करें (Section 4 का command)।
2. Render → Environment:
   - `MRK_MASTER_KEY_VERSION=2`
   - `MRK_MASTER_KEY_B64=<नई key>`
   - `MRK_MASTER_KEY_B64_V1=<पुरानी key>`
3. Save → service restart होगी।
4. अब नए payloads version 2 से बनेंगे, पुराने version 1 के payloads भी decrypt होते रहेंगे।

**सीमा:** पुरानी keys को हमेशा env में रखना पड़ेगा, वरना पुराने payloads decrypt नहीं होंगे। जब कोई पुराना payload न बचे, तो पुराने key versions हटा दें।

---

## 10. Rate Limiting (सीमा और production विकल्प)

- **In-memory limiter** (इस project में): केवल **एक Render instance** तक काम करता है।
- **Render free/starter** पर single instance होती है → ठीक है।
- **Multiple instances / autoscaling** पर → in-memory limiter **bypass** हो सकता है क्योंकि हर instance का अपना memory है।

**Production में multi-instance के लिए विकल्प:**
- **Redis** (Upstash, Render Redis) + `slowapi` / custom Redis limiter।
- **Cloudflare** rate limiting (API gateway level).
- **Render** के paid features या API Gateway.

**महत्वपूर्ण:** Rate limiting **authentication का विकल्प नहीं है** — यह सिर्फ abuse protection है।

---

## 11. CORS

- `ALLOWED_ORIGINS` में **केवल अपने frontend के HTTPS origins** डालें (comma-separated)।
- `ENV=production` पर `*` **reject होता है startup पर**।
- CORS **sirf browser** enforce करता है — यह authorization नहीं है। असली authorization Firebase token + UID check से होती है।

---

## 12. Security Limitations (स्पष्ट)

1. **Server-side encryption है, E2E नहीं।** Server master key रखने वाला admin plaintext तक पहुँच सकता है।
2. **Firebase UID ownership** किसी विशेष HTML file की पहचान प्रमाणित नहीं करता।
3. **Authorized user plaintext की copy** बना सकता है — backend नहीं रोक सकता।
4. **दोनों फोन** एक ही Firebase account + backend से payload decrypt कर सकते हैं।
5. **Master key खोने पर** उस version के सारे payloads हमेशा के लिए decrypt नहीं होंगे।
6. **पुराने browser-only payloads** अपने आप compatible नहीं होंगे — उनके मूल client-side key + algorithm चाहिए।
7. **HTTPS ज़रूरी** है। HTTP पर token leak हो सकता है।
8. **Rate limiting, monitoring, backup** production में ज़रूरी हैं।
9. **HTTPS certificate** Render automatically देता है।
10. **यह "starter" production-oriented है**, पर compliance (HIPAA, PCI आदि) के लिए additional audit ज़रूरी है।

---

## 13. Troubleshooting

| समस्या | कारण | समाधान |
|---|---|---|
| Startup पर `MRK_MASTER_KEY_B64 is not set` | env var missing | Render → Environment में set करें |
| Startup पर `must decode to 32 bytes` | key का size गलत | Section 4 का command दोबारा चलाएँ |
| Startup पर `Refusing to start: ALLOWED_ORIGINS contains '*'` | production में `*` | actual origin list करें |
| 401 Invalid Firebase ID token | token expired/revoked | frontend `getIdToken(true)` से refresh |
| 403 You do not own this payload | different Firebase account | same account से login करें |
| 400 Unable to decrypt payload | payload tampered / wrong key version | पूरा payload जैसा मिला था वैसा भेजें |
| 429 Rate limit exceeded | बहुत ज़्यादा requests | window wait करें या limits बढ़ाएँ |
| CORS error browser में | origin allow-list में नहीं | `ALLOWED_ORIGINS` में add करें |

---

## 14. Testing

```bash
# Local
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Optional tests
pip install pytest httpx
pytest -q test_main.py

# Local run (env vars set करके)
uvicorn main:app --reload --port 8000
# → http://127.0.0.1:8000/health
```

**Default ports:** Render env में `$PORT` handle होता है; local पर 8000।

---

## 15. License

अपनी आवश्यकता अनुसार उपयोग करें। कोई warranty नहीं।