# ZKST — Notatki do kolokwium

---

## 1 — Menedżery haseł (LAB-01)

### KeePass — kryptografia

| Cel | Mechanizm |
|-----|-----------|
| Poufność bazy | **AES-256** (szyfrowanie całej bazy `.kdbx`) |
| Integralność bazy | **SHA-256** / **HMAC-SHA-256** |
| Wyprowadzanie klucza | **Argon2** (v4, domyślny) lub **AES-KDF** |
| Główny klucz | kompozyt: hasło + plik klucza + konto Windows |
| Dostępność | plik lokalny — backup we własnym zakresie |

- **Odzyskiwanie dostępu** (utrata hasła): niemożliwe bez zapasowego czynnika (plik klucza / export bazy w odszyfrowanej formie) — brak backdoora
- **Generacja haseł**: CSPRNG, konfigurowalny zestaw znaków, entropia mierzona w bitach
- **Autouzupełnianie**: Auto-Type / integracja z przeglądarką przez wtyczkę

### Proton Pass — kryptografia (E2EE)

| Warstwa | Mechanizm |
|---------|-----------|
| Klucz użytkownika | **SRP-6a** (logowanie bez przesyłania hasła) → **bcrypt** → klucz symetryczny |
| Szyfrowanie haseł | **AES-256-GCM** kluczem skarbca (vault key) |
| Klucz skarbca | szyfrowany kluczem użytkownika (zasada E2EE) |
| Udostępnianie skarbca | klucz skarbca szyfrowany kluczem publicznym **OpenPGP** każdego odbiorcy |
| Protokół logowania | **SRP** — serwer nigdy nie zna hasła (Zero-Knowledge) |

- **Udostępnianie haseł**: hasło z osobna → klucz szyfrowany osobno dla każdego odbiorcy (kosztowne przy dużej liście); skarbiec (vault) → klucz skarbca szyfrowany raz per odbiorca, potem każde nowe hasło automatycznie dostępne — **efektywniejsze operacyjnie**, identyczne bezpieczeństwo kryptograficzne
- **Dostępność (recovery)**: fraza odzyskiwania (mnemonic) deszyfruje klucz użytkownika po stronie klienta — bez frazy dane bezpowrotnie utracone po zresetowaniu konta
- **Reset konta** (bez frazy): odzyskanie dostępu do konta tak, ale dane E2EE — **NIE** (klucz utracony → dane niemożliwe do odszyfrowania)
- **Ryzyko Proton Pass online**: dostawca jest punktem dystrybucji klucza publicznego; kompromitacja serwera Proton = podmiana klucza publicznego → MitM; zaufanie do infrastruktury Proton konieczne

### OTP / TOTP / FIDO

| Cecha | **TOTP (Authenticator)** | **FIDO2 / WebAuthn** |
|-------|--------------------------|----------------------|
| Standard | RFC 6238 / RFC 4226 | FIDO Alliance |
| Sekret | współdzielony seed (HMAC-SHA1) | para kluczy asymetrycznych (device-bound) |
| Odporność na phishing | ❌ podatny | ✅ odporny (origin-binding) |
| Odporność na replay | ✅ (okno 30 s) | ✅ (challenge-response) |
| Backup | export seedu (ryzyko!) | backup klucza lub rejestracja kilku urządzeń |
| Recovery przy utracie | kody zapasowe | backup-key / inna rejestracja |

- **Ryzyko TOTP**: seed = hasło; jeśli wycieknie z serwera, atakujący może generować kody bez urządzenia
- **FIDO**: klucz prywatny nigdy nie opuszcza urządzenia; przy utracie urządzenia — zarejestrowany wcześniej drugi klucz lub kody recovery
- **Proton Pass jako Authenticator**: seed TOTP zaszyfrowany w skarbcu E2EE — bezpieczne, ale wymaga dostępu do skarbca

---

## 2 — BitLocker (LAB-02)

### Architektura kluczy BitLocker

```
Dane ← szyfrowane → VMK (Volume Master Key)
VMK  ← szyfrowany → FVEK (Full Volume Encryption Key)  [w metadanych]
VMK  ← chronionym → protector (PIN / TPM / klucz odzysk.)
```

- **XTS-AES-128** (domyślny) / **XTS-AES-256** — tryb XTS dedykowany szyfrowaniu dysków (ochrona przed atakami na powiązane bloki)
- **XTS**: tweak = numer sektora; masterkey 512-bit dzielony na 2×256-bit (jeden do szyfrowania tweaka, drugi do szyfrowania danych XOR tweak) — dlatego AES-XTS-256 wymaga klucza 512-bit

### TPM + Secure Boot — mechanizm ochrony integralności

- **TPM mierzy PCR** (Platform Configuration Registers) = hasz komponentów bootu (firmware, bootloader, konfiguracja)
- Przy zmianie firmware (aktualizacja UEFI) → PCR nie zgadza się → **TPM odmawia wydania VMK** → system żąda klucza odzyskiwania
- **Zwykłe aktualizacje systemu** nie modyfikują mierzonych komponentów → brak reakcji TPM
- **Aktualizacje firmware przez Windows Update** → BitLocker wchodzi w tryb "dysk zaszyfrowany, BitLocker wyłączony, klucz na dysku" → PCR przeliczane po aktualizacji → VMK aktualizowany w TPM → BitLocker powraca do normalnego trybu — użytkownik nic nie odczuwa

### Klucz odzyskiwania

- Postać: **osiem grup po 6 cyfr** (48 cyfr łącznie)
- Identyfikuje się go po **ID klucza** wyświetlanym na ekranie odblokowania
- Zapisany w: plik, druk, konto Microsoft, AD/Azure AD

### Scenariusz z pytania (img 1/img 2)

- **Chronione atrybuty domyślnie**: **Poufność** danych na dysku + **Integralność** procesu rozruchu (częściowa)
- **Naruszony atrybut**: Integralność rozruchu (zmiana firmware → PCR niezgodne)
- **Wykrycie naruszenia**: UEFI/Secure Boot mierzy PCR przy starcie; TPM weryfikuje
- **Reakcja systemu**: TPM kasuje VMK → wyświetlenie żądania klucza odzyskiwania
- **Co robi użytkownik**: wpisuje 48-cyfrowy klucz odzyskiwania
- **Windows Update firmware**: dziś możliwe, ale BitLocker automatycznie obsługuje ten scenariusz (tryb tymczasowego wyłączenia)

### Konfiguracja BitLocker — kluczowe flagi GPO

| Ustawienie | Lokalizacja GPO |
|------------|-----------------|
| Rozszerzone PIN (alfanumeryczne) | `Computer Config → Admin Templates → Windows Components → BitLocker → OS Drives → Allow enhanced PINs` |
| Zakaz zmiany PIN przez użytkownika | odpowiednia polityka użytkownika |
| Zakaz wyłączenia BitLocker | `Deny write access to fixed data drives...` |
| Blokada plug-and-play (sesja zablokowana) | `Prevent installation of devices...` |
| Auto-odblokowanie dysku zewnętrznego | `BitLocker → Removable Drives → Allow auto-unlock` |
| Zakaz zapisu na niezaszyfrowane dyski | `Deny write access to removable drives not protected by BitLocker` |

### Zmiana algorytmu XTS-AES-128 → XTS-AES-256

1. GPO: ustaw `Choose drive encryption method → XTS-AES-256`
2. `manage-bde -off C:`  → odszyfrowanie woluminu
3. `manage-bde -on C: -used` → ponowne szyfrowanie (nowym algorytmem)
4. Weryfikacja: `manage-bde -status C:` → pole "Encryption Method"
5. Klucz odzyskiwania po zmianie: **inny** (nowy VMK, nowy FVEK) — stary klucz nie działa

---

## 3 — LUKS (LAB-03)

### Architektura kluczy LUKS2

```
Dane ← AES-XTS-512-bit-masterkey → Volume
MasterKey (512-bit) ← szyfrowany → w Keyslot[n] (hasłem / plikiem / tokenem)
Keyslot ← wyprowadzenie klucza → Argon2 (PBKDF2 w LUKS1)
```

- **LUKS2** ma **32 keysloты**; każdy keyslot = niezależna kopia masterkey zaszyfrowana innym czynnikiem
- **Masterkey** nigdy nie jest bezpośrednio dostępny w postaci jawnej w systemie plików
- **AES-XTS**: masterkey 512-bit → 2×256-bit (tweak key + data key) — dlatego 256-bit wystarczy entropią

### Domyślne parametry LUKS2

| Parametr | Domyślna wartość |
|----------|-----------------|
| Szyfr | **aes-xts-plain64** |
| Rozmiar klucza | **512 bit** (= AES-256 w trybie XTS) |
| KDF | **Argon2id** |
| Hash (PBKDF2 legacy) | SHA-256 |

### Komendy LUKS — ściągawka

```bash
# Tworzenie zaszyfrowanej partycji
cryptsetup luksFormat /dev/sdX

# Otwarcie (montowanie)
cryptsetup luksOpen /dev/sdX nazwa_mapowania
mount /dev/mapper/nazwa_mapowania /mnt/punkt

# Zamknięcie
umount /mnt/punkt
cryptsetup luksClose nazwa_mapowania

# Weryfikacja parametrów
cryptsetup luksDump /dev/sdX

# Dodanie hasła (slot)
cryptsetup luksAddKey /dev/sdX

# Zmiana hasła (konkretny slot)
cryptsetup luksChangeKey /dev/sdX

# Generacja pliku klucza (losowe dane)
dd if=/dev/urandom of=/root/.lukskey bs=512 count=1
chmod 400 /root/.lukskey

# Dodanie pliku klucza jako czynnika
cryptsetup luksAddKey /dev/sdX /root/.lukskey

# Otwarcie plikiem klucza
cryptsetup luksOpen /dev/sdX nazwa --key-file /root/.lukskey
```

### Scenariusz Wiktorii — kluczowe wnioski

- **Metoda odblokowania dla laika** → **hasło** (najprostsze; bez potrzeby zarządzania plikami kluczy lub tokenami)
- **3 wskazówki dla Wiktorii**: (1) użyj silnego hasła (passphrase ≥ 4 słowa), (2) zapamiętaj hasło lub zapisz bezpiecznie, (3) zrób backup klucza odzyskiwania lub samego masterkey
- **Dodanie drugiego czynnika** dla Maćka: `cryptsetup luksAddKey /dev/sdX` → osobne hasło dla brata → każdy ma swój slot, masterkey ten sam → **TAK, możliwe** (LUKS obsługuje wiele keyslotów)
- **Szyfrowanie dysku z istniejącymi danymi** (dysk babci):
  1. Backup danych (kopia na inny nośnik)
  2. `cryptsetup luksFormat /dev/sdX` (formatuje i tworzy LUKS header)
  3. `cryptsetup luksOpen /dev/sdX vol && mkfs.ext4 /dev/mapper/vol`
  4. Przywróć dane z backupu
  - ⚠ **Nie istnieje metoda bezstratna online** dla partycji bez wolnego miejsca — wymagany backup
  - Alternatywa: `cryptsetup-reencrypt --encrypt` (LUKS2) — szyfrowanie in-place z ryzykiem utraty danych przy błędzie

- **Rozmiar pliku klucza**: **256 bitów = 32 bajty** minimum (entropia wystarczająca dla AES-256); konwencjonalnie **512-bit = 64 bajty** (dd count=1 bs=512 daje 4096-bit — nadmiar, ale bezpieczny); LUKS używa całego pliku jako źródła entropii
- **Ochrona przed Maćkiem przy otwartym komputerze**: odmontować wolumin (`cryptsetup luksClose`) + ustawić odpowiednie uprawnienia systemu plików (chmod 700 na katalog) lub wylogować sesję

---

## 4-5 — Usługi Proton (LAB-04-05)

### Kryptografia Proton — przegląd

| Usługa | Standard | Klucze |
|--------|----------|--------|
| **Proton Mail** | **OpenPGP** (RFC 9580) | klucz per konto, generowany po stronie klienta |
| **Proton Drive** | **OpenPGP** / AES-256-GCM | klucze pliku szyfrowane kluczem folderu, klucze folderów szyfrowane kluczem udziału |
| **Proton Calendar** | **OpenPGP** | klucze zdarzeń szyfrowane kluczem kalendarza |
| **Proton Pass** | SRP + AES-256-GCM | klucze skarbca szyfrowane kluczem użytkownika |

- Wszystkie usługi: **E2EE** + **Zero-Knowledge** — serwery Proton nie mają dostępu do treści
- Klucz prywatny przechowywany na serwerze w postaci zaszyfrowanej (hasłem konta przez SRP)

### Proton Mail — scenariusze wysyłki

| Adresat | Szyfrowanie domyślne | Mechanizm |
|---------|---------------------|-----------|
| **Proton → Proton** | ✅ E2EE automatycznie | klucz publiczny OpenPGP adresata pobrany z serwera Proton |
| **Proton → zewnętrzny** | ❌ brak E2EE (TLS only) | standardowy e-mail przez SMTP + TLS |
| **Proton → zewnętrzny + hasło** | ✅ szyfrowanie symetryczne | AES-256, adresat otrzymuje link; klucz = hasło podane przez nadawcę |
| **Proton → zewnętrzny + import klucza OpenPGP** | ✅ E2EE | klucz publiczny zewnętrznego użytkownika importowany do kontaktu w Proton |

- Gdy nadawca importuje klucz OpenPGP zewnętrznego adresata: **szyfrowanie asymetryczne** (OpenPGP), adresat odczytuje swoim kluczem prywatnym
- Proton Mail **automatycznie podpisuje** wysyłane wiadomości kluczem prywatnym nadawcy (w ustawieniach konta)
- Treść wiadomości szyfrowana; temat, nadawca, adresat, data **widoczne w metadanych** (konieczność ze względu na routing SMTP)

### Proton — odzyskiwanie danych

- **Recovery phrase (fraza odzyskiwania)** = jedyna metoda deszyfrowania kluczy po resecie hasła konta
- Reset konta bez frazy → **dane E2EE bezpowrotnie utracone** (Zero-Knowledge by design)
- Po odzyskaniu konta bez frazy: nowe klucze → stare zaszyfrowane dane = niedostępne
- **Weryfikacja po odzysku**: e-mail, plik Drive, zdarzenie Calendar = niedostępne (brak klucza prywatnego)

### Proton Calendar — kryptografia

- Każde zdarzenie szyfrowane kluczem kalendarza (OpenPGP)
- Klucz kalendarza szyfrowany kluczem użytkownika
- **Udostępnienie zdarzenia**: klucz kalendarza lub klucz zdarzenia szyfrowany kluczem publicznym odbiorcy
- Metadane zdarzenia (tytuł, opis, lokalizacja) zaszyfrowane; serwer widzi jedynie czas i identyfikatory

### Proton Drive — kryptografia

- Hierarchia kluczy: klucz udziału → klucz folderu → klucz pliku
- **Udostępnianie przez link**: klucz pliku szyfrowany hasłem linku (PGP symmetric)
- Udostępnianie użytkownikowi: klucz udziału szyfrowany kluczem publicznym odbiorcy
- Zajętość dysku: plik udostępniony przez innego = wlicza się do dysku **właściciela**, nie odbiorcy (w przeciwieństwie do niektórych dostawców)

### Wysyłka do instytucji z OpenPGP (img 6)

1. Pobierz klucz publiczny instytucji z serwera kluczy OpenPGP
2. Dodaj go do kontaktu w Proton Mail
3. Wyślij wiadomość → Proton automatycznie zaszyfruje kluczem OpenPGP instytucji
4. Adresat odczytuje swoim kluczem prywatnym
- Kryptografia: **asymetryczna** (OpenPGP) + podpis nadawcy → E2EE, autentyczność, integralność

---

## 6-7 — OpenPGP (LAB-06-07)

### Struktura klucza OpenPGP

```
Klucz główny (primary key) — atrybut C (Certify)
│   └── tożsamości (UID): imię, nazwisko, e-mail
├── podklucz do podpisywania     [S]
├── podklucz do szyfrowania      [E]
└── podklucz do uwierzytelniania [A]
```

- **Atrybuty kluczy (flags)**: **C** = certyfikacja (podpisywanie kluczy), **S** = podpis, **E** = szyfrowanie, **A** = uwierzytelnianie
- Klucz główny domyślnie **CSE** (Certify + Sign + Encrypt) — zła praktyka; zalecane: klucz główny = tylko **C**, reszta w podkluczach
- **Atrybut wymagany do podpisania podklucza**: **C** (Certify) — wyłącznie klucz główny może certyfikować podklucze i tożsamości

### Fingerprint / Odcisk klucza

- Wyznaczany z **klucza głównego** (public key packet) → zmiana podkluczy nie zmienia fingerprinta
- Dodanie podklucza → fingerprint **bez zmian**; rozmiar klucza publicznego eksportowanego rośnie
- Weryfikacja autentyczności fingerprinta: **osobiście** (face-to-face) lub bezpiecznym kanałem bocznym (telefon ze znaniem głosu)

### Algorytmy — porównanie

| Typ | Algorytm | Zalety | Uwagi |
|-----|----------|--------|-------|
| Asymetryczny klasyczny | **RSA-3072 / RSA-4096** | szeroka kompatybilność | duży klucz, wolny |
| Asymetryczny ECC | **Ed25519** (podpis) / **X25519** (szyfr) | mały klucz, szybki | nowoczesny, OpenPGP v4+ |
| Krzywa NIST | **P-256, P-384, P-521** | kompatybilność z FIPS | zaufanie do NIST |

- **RSA-3072** = minimalny zalecany rozmiar (równoważnik 128-bit symetryczny)
- Czas życia klucza: algorytm musi być bezpieczny przez cały okres ważności klucza — dobierz datę ważności odpowiednio

### Generacja klucza — komendy GPG

```bash
# Standardowy klucz (Ed25519 + X25519, interaktywny)
gpg --gen-key

# Klucz z pełną kontrolą parametrów
gpg --expert --full-generate-key

# Dodanie podklucza (wymaga --expert dla ECC)
gpg --expert --edit-key FINGERPRINT
gpg> addkey   # wybierz typ i parametry

# Unieważnienie podklucza
gpg --edit-key FINGERPRINT
gpg> key N    # wybierz numer podklucza
gpg> revkey

# Eksport kluczy
gpg --armor --export EMAIL > pub.asc
gpg --armor --export-secret-keys EMAIL > priv.asc
gpg --armor --export-secret-subkeys EMAIL > subkeys.asc
```

> ⚠ `--export-secret-keys` eksportuje **wszystkie** klucze prywatne (główny + podklucze) — klucze prywatne **nigdy** nie powinny opuszczać urządzenia; eksport naraża je na kompromitację; w keyringu zabezpieczone hasłem, poza — podatne

### SSH z kluczem OpenPGP

```bash
# Strona klienta (Alicja)
gpg --export-ssh-key FINGERPRINT >> ~/.ssh/authorized_keys_to_send
# lub
gpg --export-ssh-key FINGERPRINT   # kopia do serwera

# Konfiguracja gpg-agent jako agent SSH
echo "enable-ssh-support" >> ~/.gnupg/gpg-agent.conf
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)

# Strona serwera (Bob) - dodanie klucza Alicji
# Skopiuj SSH public key Alicji do ~/.ssh/authorized_keys na koncie 'alicja26'

# Zakaz logowania hasłem (serwer SSH)
# /etc/ssh/sshd_config:
PasswordAuthentication no
PubkeyAuthentication yes
```

- Klucz SSH eksportowany z OpenPGP = **podklucz z atrybutem A** (Authentication)
- Bez podklucza A → niemożliwe logowanie SSH przez GPG

### Szyfrowanie i podpisywanie pliku — komendy

```bash
# Szyfrowanie do wielu odbiorców (klucz Prowadzącego + własny)
gpg --encrypt -r prowadzacy@email -r moj@email --armor plik.txt

# Podpisanie (detached signature)
gpg --detach-sign --armor plik.txt   # → plik.txt.asc

# Podpisanie + szyfrowanie
gpg --sign --encrypt -r prowadzacy@email -r moj@email plik.txt

# Weryfikacja podpisu
gpg --verify plik.txt.sig plik.txt

# Deszyfrowanie
gpg --decrypt plik.txt.gpg > plik_odszyfrowany.txt
```

- Aby odczytać zaszyfrowany plik: **własny klucz prywatny** (podklucz E lub klucz główny z atrybutem E)
- Aby zweryfikować podpis: **klucz publiczny nadawcy**

### Web of Trust (WoT) — mechanizm

| Poziom trust (zaufanie właściciela) | Skutek dla validity (ważność klucza) |
|-------------------------------------|--------------------------------------|
| **ultimate** | klucz sam w sobie ważny (jak własny) |
| **full** | 1 podpis full = klucz ważny |
| **marginal** | wymagane ≥ 3 podpisy marginal = klucz ważny |
| **undefined/none** | klucz niezaufany |

- **Trust (zaufanie)** = co MY uważamy o właścicielu klucza (czy weryfikuje tożsamości rzetelnie)
- **Validity (ważność)** = wyliczana przez GPG na podstawie sieć podpisów i ustawień trust
- Własny klucz zawsze = **ultimate**
- Klucz podpisany kluczem z trust=full → validity = **full**
- Klucz podpisany 3 kluczami z trust=marginal → validity = **full**

### WoT dla organizacji

- **CA-like structure**: klucz organizacji (ultimate) podpisuje klucze działów; klucze działów (full) podpisują klucze pracowników
- Linia certyfikacji (signing path) musi być nieprzerwana i możliwa do prześledzenia
- Głębokość WoT w GPG: domyślnie 5 poziomów; `--trust-model pgp`

---

## 8 — Komunikator Signal (LAB-08)

### Podstawy Signal

- Protokół: **Signal Protocol** (Double Ratchet Algorithm + X3DH key agreement)
- Szyfrowanie: **E2EE** (end-to-end) dla wszystkich wiadomości, połączeń głosowych i wideo
- **Zero-Knowledge**: serwer Signal nie ma dostępu do treści wiadomości
- Rejestracja: wymaga **numeru telefonu** (identyfikator); możliwość ustawienia **nazwy użytkownika** (ukrywa numer)
- Nazwa użytkownika: **case-insensitive**; zakończona cyfrą; zmiana możliwa; opcjonalna

### Ochrona przed MitM — weryfikacja bezpieczeństwa

- Mechanizm: **Safety Numbers** (odcisk sesji kryptograficznej) = 60-cyfrowy kod lub QR
- Weryfikacja: porównanie Safety Numbers z rozmówcą **osobiście** lub bezpiecznym kanałem bocznym
- Jeśli numery zgodne → brak MitM; jeśli niezgodne → sesja skompromitowana

### Synchronizacja Signal Desktop

| Element | Synchronizowany | Uwaga |
|---------|-----------------|-------|
| Wiadomości nowe | ✅ tak | od momentu parowania |
| Historia wiadomości | ❌ nie | historia pozostaje na telefonie |
| Kontakty | ✅ tak | |
| Ustawienia | częściowo | |
| Klucze sesji | ✅ tak | każde urządzenie ma swoje klucze (multi-device Signal Protocol) |

- Po odpinaniu i ponownym parowaniu: historia z okresu rozparowania **nie jest synchronizowana** (wiadomości zaszyfrowane kluczami nieistniejącymi już na Desktop)
- **Dlaczego historia nie jest synchronizowana**: klucze ratchet są per-sesja, unikalne; serwer przechowuje zaszyfrowane wiadomości tymczasowo (do dostarczenia) — nie ma możliwości retroszyfrowania

### Grupy w Signal

- Administracja grupą: twórca = administrator; możliwość dodawania adminów
- Bezpieczeństwo: każdy uczestnik posiada klucze grupowe; wyjście/dodanie = rotacja kluczy (forward secrecy)
- Maksymalna liczba uczestników: **1000** (grupy), połączenia głosowe/wideo: zależnie od platformy (typowo ~8 dla połączeń)

### Konfiguracje zwiększające bezpieczeństwo Signal

| Ustawienie | Cel |
|------------|-----|
| **PIN rejestracyjny** (Registration Lock) | ochrona przed przejęciem numeru przez SMS |
| **Znikające wiadomości** (Disappearing messages) | minimalizacja ekspozycji danych |
| **Blokada ekranu** | ochrona lokalna |
| **Powiadomienia bez treści** | ochrona metadanych na ekranie blokady |
| **Ukrycie numeru telefonu** (nazwa użytkownika) | ochrona prywatności identyfikatora |
| **Note to Self jako bezpieczny notatnik** | E2EE storage |
| Weryfikacja Safety Numbers | ochrona przed MitM |

---

## 9 — Podpis elektroniczny i usługi zaufania (LAB-09)

### Rodzaje podpisów elektronicznych — porównanie

| Cecha | **Podpis zaufany** | **Podpis osobisty** | **Podpis kwalifikowany** |
|-------|--------------------|---------------------|--------------------------|
| Podstawa prawna | eIDAS + ustawa PL | eIDAS (zaawansowany) | eIDAS (kwalifikowany) |
| Równoważny z odręcznym | ✅ (w Polsce, ePUAP) | ✅ (zaawansowany) | ✅ (najwyższy poziom EU) |
| Wymagany klucz | profil zaufany | e-dowód (certyfikat osobisty) | kwalifikowane urządzenie + certyfikat CA |
| Koszt | bezpłatny | bezpłatny (e-dowód) | płatny (karta + certyfikat) |
| Ważność profilu | **3 lata** | jak e-dowód (10 lat) | do wygaśnięcia certyfikatu |
| Limit podpisów | brak (zaufane); kwalif. **5/miesiąc** (mObywatel free) | brak | zależy od dostawcy |
| Aplikacja | pz.gov.pl, ePUAP | mObywatel / czytnik e-dowód | oprogramowanie dostawcy |

- **Podpis odręczny w PDF (narysowany)** = podpis elektroniczny ✅ jeśli użytkownik traktuje go jako swój — ale **brak mocy prawnej** porównywalnej z kwalifikowanym
- **Ważny akt prawny EU**: **eIDAS** (Regulation (EU) No 910/2014) — normuje podpisy elektroniczne, usługi zaufania w całej UE
- Nowa wersja: **eIDAS 2.0** (2024)

### Profil zaufany — wymagania i dane logowania

**Wymagania do założenia profilu zaufanego:**
- Obywatelstwo/zamieszkanie: **dowolna osoba z numerem PESEL**
- Wiek: **od 13 lat** (zdolność do czynności prawnych — pełna lub ograniczona)
- Posiadanie: **numer PESEL**
- ⚠ Cudzoziemka z innego kraju może założyć profil zaufany o ile **posiada PESEL**

**Dane do logowania do profilu zaufanego:**
- **login (email)** + **hasło** + **kod autoryzacyjny** (SMS lub aplikacja)

### Formaty podpisów

| Format | Zastosowanie | Typ |
|--------|-------------|-----|
| **PAdES** | tylko pliki PDF | podpis wewnątrz PDF |
| **XAdES** | dowolne pliki (XML-based) | podpis w osobnym pliku lub wewnątrz XML |
| **CAdES** | dowolne pliki (CMS-based) | podpis opakowany binarnie |

- Podpis zaufany obsługuje: **PAdES** (PDF) i **XAdES** (pozostałe pliki)
- Modyfikacja podpisanego PDF → podpis **unieważniony** (weryfikator wykrywa zmianę); przeglądarka PDF wyświetla ostrzeżenie

### PKI — weryfikacja certyfikatu (img 5 — Patrycja)

**Aplikacja do graficznego zarządzania PKI**: **XCA** (X Certificate and Key management)

**Weryfikacja certyfikatu wykładowcy (wydanego przez pośrednie CA):**
1. Sprawdź **datę ważności** certyfikatu wykładowcy
2. Sprawdź **datę ważności** certyfikatu pośredniego CA + głównego CA
3. Sprawdź, czy żaden certyfikat w łańcuchu **nie figuruje na liście CRL** (wydanej przez odpowiednie CA)
4. Zweryfikuj **podpisy CA** — całą ścieżkę certyfikacji od certyfikatu wykładowcy przez pośrednie CA do głównego (root CA)

**Gdzie znaleźć CRL**: serwer CRL podany w polu **CRL Distribution Point** (CDP) w certyfikacie → dla WAT: serwer `pk.wat.edu.pl`

### PKI — atrybuty użycia kluczy

| Atrybut (Key Usage) | Kod | Zastosowanie |
|---------------------|-----|-------------|
| **digitalSignature** | S | podpisy cyfrowe |
| **contentCommitment** / nonRepudiation | — | niezaprzeczalność |
| **keyEncipherment** | E | szyfrowanie kluczy sesji (RSA) |
| **dataEncipherment** | E | bezpośrednie szyfrowanie danych |
| **keyAgreement** | A | uzgodnienie klucza (DH/ECDH) |
| **keyCertSign** | C | podpisywanie certyfikatów (CA) |
| **cRLSign** | — | podpisywanie list CRL |

### Scenariusz z agentami — CRL (img 9/10)

**Dane ze scenariusza:**
- Z, O: samopodpisane (root CA) — mogą: podpisywać certyfikaty, tworzyć CRL
- Z → certyfikaty dla M, T, B (znaki: podpisywanie cert., CRL, szyfrowanie) + M (podpis cyfrowy) + B (deszyfrowanie)
- B → U: szyfrowanie only; U → K: CRL + podpis cyfrowy + deszyfrowanie
- O → P: szyfrowanie kluczy; W → P: podpisywanie certyfikatów + CRL; A ← O: podpisy cyfrowe + certyfikaty + CRL
- A → P: podpis + CRL + podpisywanie certyfikatów; P → G: szyfrowanie; P → Q: deszyfrowanie; P+G: podpis cyfrowy dla G

**Weryfikacja certyfikatu K → które listy CRL sprawdzić:**
Ścieżka: K ← U (wystawca K) ← B (wystawca U) ← Z (wystawca B)
- CRL wystawiona przez **U** (czy K nie jest unieważniony)
- CRL wystawiona przez **B** (czy U nie jest unieważniony)
- CRL wystawiona przez **Z** (czy B nie jest unieważniony)
- Opcjonalnie CRL wystawiona przez **O** (jeśli Z/O są powiązane)

**Klucz**: każdy CA wystawia CRL dla **certyfikatów, które sam podpisał**; sprawdzamy CRL wystawców na każdym poziomie ścieżki certyfikacji

### Dane zawarte w podpisach

| Pole | Podpis zaufany | Podpis osobisty | Podpis kwalifikowany |
|------|---------------|-----------------|----------------------|
| Imię i nazwisko | ✅ | ✅ | ✅ |
| PESEL | ✅ | ✅ | ❌ (opcjonalnie) |
| Data i czas | ✅ | ✅ | ✅ (znacznik czasu TSA) |
| Certyfikat CA | ✅ | ✅ | ✅ |
| Numer seryjny certyfikatu | ✅ | ✅ | ✅ |

- Podpis kwalifikowany: znacznik czasu od **TSA (Time Stamping Authority)** → niepodważalny czas złożenia podpisu
- Podpis zaufany i osobisty: czas z systemu lokalnego → mniej wiarygodny bez TSA

---

## Szybka ściągawka — kluczowe pojęcia

| Pojęcie | Definicja |
|---------|-----------|
| **E2EE** | szyfrowanie end-to-end — klucze tylko u komunikujących się stron |
| **Zero-Knowledge** | dostawca usługi nie ma dostępu do klucza szyfrującego |
| **Forward Secrecy** | kompromitacja klucza długoterminowego nie ujawnia poprzednich sesji |
| **PCR** | Platform Configuration Register — rejestr hashów komponentów bootu w TPM |
| **VMK** | Volume Master Key — klucz szyfrujący wolumin BitLocker |
| **FVEK** | Full Volume Encryption Key — faktyczny klucz danych BitLocker |
| **KDF** | Key Derivation Function — Argon2, PBKDF2, bcrypt |
| **LUKS Keyslot** | niezależny slot z kopią masterkey zaszyfrowaną innym czynnikiem |
| **WoT** | Web of Trust — sieć wzajemnych certyfikacji kluczy OpenPGP |
| **CRL** | Certificate Revocation List — lista unieważnionych certyfikatów |
| **TSA** | Time Stamping Authority — zaufany urząd znacznika czasu |
| **SRP** | Secure Remote Password — uwierzytelnienie bez przesyłania hasła |
| **eIDAS** | rozporządzenie UE normujące podpisy elektroniczne i usługi zaufania |
| **Safety Numbers** | 60-cyfrowy odcisk sesji Signal do weryfikacji braku MitM |
| **Double Ratchet** | algorytm protokołu Signal — zapewnia forward secrecy i break-in recovery |
