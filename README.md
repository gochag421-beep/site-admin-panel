# Vexon Security Scanner 1.1

Windows desktop εφαρμογή για εξουσιοδοτημένο, περιορισμένο έλεγχο HTTP/TLS configuration. Ελληνικό GUI με ευρήματα, URLs, κάλυψη, σφάλματα, ακύρωση και JSON export.

## Εκτέλεση / build

Απαιτεί Node.js 22+ (το CI χρησιμοποιεί 24).

```sh
npm ci
npm test
npm start
npm run build:win
```

Το build παράγει x64 NSIS installer και portable EXE στο dist/. Το GitHub Action εκτελεί tests, dependency audit και build σε push στο main, pull request ή manual dispatch. Κατέβασε το artifact Vexon-Security-Scanner-Windows από επιτυχημένο run.

Τα EXE είναι unsigned. Για εμπορική διανομή απαιτείται δικό σου πιστοποιητικό code signing. Δεν υπάρχει αυτόματο update.

## Χρήση

1. Δώσε πλήρες HTTP/HTTPS URL και επιβεβαίωσε ότι έχεις άδεια ελέγχου.
2. Προαιρετικά όρισε μέγιστες σελίδες στις Ρυθμίσεις (1–20) και αποθήκευσέ τες.
3. Δες ευρήματα, URLs, TLS, κάλυψη και τυχόν αποτυχίες. Η ακύρωση διατηρεί όσα έχουν συλλεχθεί.
4. Για AI, πρόσθεσε OpenRouter key, άνοιξε την προεπισκόπηση και επιβεβαίωσε αποστολή. Έπειτα η επιλογή και εναλλαγή δωρεάν μοντέλων είναι αυτόματη.
5. Εξήγαγε JSON για μόνιμη αποθήκευση. Η τελευταία αναφορά κρατιέται στη μνήμη και χάνεται όταν κλείσει η εφαρμογή.

Κενό πεδίο key διατηρεί το προηγούμενο κρυπτογραφημένο κλειδί. Υπάρχει ξεχωριστό κουμπί διαγραφής. Η αποθήκευση χρησιμοποιεί Electron safeStorage (Windows DPAPI). Κατεστραμμένες ρυθμίσεις εμφανίζουν σφάλμα αντί να αντικαθίστανται σιωπηρά.

## Πραγματική κάλυψη

- Επαλήθευση TLS certificate/hostname/trust μέσω κανονικής HTTPS σύνδεσης, λήξη και negotiated protocol.
- Security headers, βασικές αδύναμες ρυθμίσεις CSP/HSTS, cookie attributes.
- CORS wildcard/credentials ως configuration warning, όχι απόδειξη διαρροής.
- HTTP resources και form actions, cross-origin scripts/styles χωρίς SRI.
- Same-origin links από στατικό HTML. Δεν εκτελεί JavaScript, login, exploit payloads ή υποβολή φορμών.
- Δεν ελέγχει backend κώδικα, CVEs εφαρμογής, SQL injection, authorization, πλήρη TLS cipher suites ή όλες τις μορφές mixed content (π.χ. CSS imports/srcset).

Το score είναι ευρετικός δείκτης ρυθμίσεων, όχι πιστοποίηση ασφάλειας. Κάθε κατηγορία ευρήματος αφαιρεί βαθμούς μία φορά. Σε failed/partial/cancelled scans ή χωρίς HTML εμφανίζεται κενό score. Τα info δεν αφαιρούν βαθμούς.

## Δικτυακά όρια και ιδιωτικότητα

- Μόνο default HTTP/HTTPS ports. Απορρίπτονται URL credentials και μη δημόσιες IPv4/IPv6 διευθύνσεις, συμπεριλαμβανομένων IPv4-mapped.
- Κάθε αίτημα επιλύει/ελέγχει όλες τις DNS διευθύνσεις και συνδέεται σε μία επαληθευμένη IP, με το αρχικό hostname για Host/TLS verification.
- Ακολουθεί ίδιο origin και αρχική αναβάθμιση HTTP→HTTPS στο ίδιο hostname. Διαφορετικό hostname (και www) απαιτεί νέα εξουσιοδοτημένη σάρωση.
- 500 ms μεταξύ αιτημάτων, μέχρι 20 επιτυχείς σελίδες, μέχρι maxPages+5 συνολικές προσπάθειες, 5 redirects και ουρά μέχρι 100 URLs.
- DNS timeout 5s, request/body timeout 12s, HTML μέχρι 2 MB, συνολική σάρωση μέχρι 3 λεπτά. Μη HTML bodies δεν κατεβαίνουν. Μη αναμενόμενη συμπίεση απορρίπτεται.
- Τιμές cookies δεν αποθηκεύονται. Query values και URL credentials αφαιρούνται από αναφορές. URL paths και ονόματα παραμένουν: έλεγξε την προεπισκόπηση για εμπιστευτικά στοιχεία πριν επιτρέψεις αποστολή.
- Η AI παίρνει περιορισμένο allowlist πεδίων, μέχρι 100 ευρήματα και 1.000 χαρακτήρες ανά πεδίο. Δεν παίρνει raw HTML ή cookie values. Τα δεδομένα μεταφέρονται στο OpenRouter και στους παρόχους του, με τις πολιτικές τους.

## OpenRouter free-only και fallback

Σε κάθε ανάλυση ανακτάται νέο /models catalog. Επιτρέπονται μόνο μοντέλα με μηδενικό prompt/completion και μηδενικά όλα τα παρεχόμενα pricing fields. Απορρίπτονται ασαφείς τιμές και non-text outputs. Τίθενται επιπλέον provider max_price=0 για prompt/completion/request. Η λίστα ταξινομείται κατά context και αποκλείονται γνωστά ανεπαρκή context windows.

Προσωρινά errors, network failures, κενές/κομμένες απαντήσεις και provider rate limits οδηγούν αυτόματα στο επόμενο επαληθευμένο δωρεάν μοντέλο. Provider-specific cooldown δεν σταματά όλη τη λίστα. Account-wide ημερήσια όρια και 401/402 σταματούν με σαφές μήνυμα· δεν παρακάμπτονται με αλλαγή μοντέλου. Άγνωστο/account-level Retry-After πάνω από 60s σταματά αντί να αγνοηθεί. Μέχρι 3 προσπάθειες catalog, 45s ανά AI request και 3 λεπτά συνολικά, με ακύρωση.

Δεν υπάρχει paid fallback. Η διαθεσιμότητα και τα account limits του OpenRouter εξακολουθούν να ισχύουν. Κάθε αποτυχία διατηρεί τη βασική αναφορά και ιστορικό προσπαθειών.

## Tests

Τα tests χρησιμοποιούν mocks, συνθετικές αναφορές και προσωρινά αρχεία. Δεν κάνουν scans σε τρίτα συστήματα ούτε πραγματικές κλήσεις AI. Καλύπτουν SSRF/IP validation, pinned lookup, body size/timeouts, redirects, privacy, partial scores, cancellation, settings persistence και free-only failover.

