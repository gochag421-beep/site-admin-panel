# Vexon Security Scanner

Windows desktop εφαρμογή για **εξουσιοδοτημένο, αμυντικό** έλεγχο ιστοσελίδων. Εκτελεί παθητικούς ελέγχους TLS/HTTPS, security headers, cookies, CORS, mixed content και third-party assets. Προαιρετικά στέλνει μόνο τη δομημένη αναφορά στο OpenRouter, επιλέγει αυτόματα διαθέσιμο δωρεάν μοντέλο και δημιουργεί ελληνικό πλάνο διόρθωσης.

## Εκτέλεση για ανάπτυξη

```bash
npm install
npm start
```

## Δημιουργία Windows `.exe`

Κάθε push στο `main` ξεκινά το GitHub Action **Build Windows EXE**. Από τη σελίδα Actions άνοιξε το τελευταίο επιτυχημένο run και κατέβασε το artifact `Vexon-Security-Scanner-Windows`. Περιέχει installer και portable `.exe`.

Το build είναι unsigned. Τα Windows μπορεί να εμφανίσουν SmartScreen μέχρι να προστεθεί πιστοποιητικό code signing.

## OpenRouter

Δημιούργησε API key στο OpenRouter και πρόσθεσέ το στις Ρυθμίσεις. Αποθηκεύεται κρυπτογραφημένο με το Electron `safeStorage`/Windows DPAPI. Η εφαρμογή ανακτά τη λίστα μοντέλων σε κάθε AI ανάλυση, φιλτράρει τα δωρεάν και επιλέγει αυτόματα ένα διαθέσιμο μοντέλο με μεγάλο context.

## Όρια ασφαλείας

- Απαιτεί ρητή επιβεβαίωση εξουσιοδότησης.
- Επιτρέπει μόνο HTTP/HTTPS στις θύρες 80/443.
- Μπλοκάρει localhost, ιδιωτικές και link-local IP για προστασία από SSRF.
- Περιορίζεται σε 20 same-origin σελίδες, χωρίς exploit payloads, brute force ή παράκαμψη login.
- Δεν αντικαθιστά επαγγελματικό penetration test ή code review.
