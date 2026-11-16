# Web sigurnosni laboratorij

Aplikacija za SQL Injection i Broken Authentication.

## Preduvjeti

- Node.js 20 ili noviji
- PostgreSQL

## Lokalno pokretanje na Windowsu

1. U PostgreSQL-u napravi bazu `web2_security_lab`.
2. u `.env` staviti parametre baze (PORT, DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME).
3. u `.env` također staviti PORT=3000 i IP=127.0.0.1
4. U Command Promptu ili PowerShellu, iz mape `lab2`, pokreni:

   ```powershell
   npm.cmd install
   npm.cmd test
   npm.cmd start
   ```

5. Otvori `http://127.0.0.1:3000`.

Pri prvom pokretanju aplikacija stvara tablicu i dva sintetička korisnika.
Zaštićeni način rada je početni. Testni računi koriste zaporku `demo123`:

- `demo-admin` — administratorska uloga
- `demo-user` — korisnička uloga
