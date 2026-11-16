# Web sigurnosni laboratorij

Lokalna demonstracijska aplikacija za SQL Injection i Broken Authentication.
Koristi samo izmišljene račune i lokalnu PostgreSQL bazu.

## Preduvjeti

- Node.js 20 ili noviji
- PostgreSQL

## Pokretanje na Windowsu

1. U PostgreSQL-u napravi bazu `web2_security_lab`.
2. Kopiraj `.env.example` u `.env` i podesi lokalne PostgreSQL vjerodajnice.
3. U Command Promptu ili PowerShellu, iz mape `lab2`, pokreni:

   ```powershell
   npm.cmd install
   npm.cmd test
   npm.cmd start
   ```

4. Otvori `http://127.0.0.1:3000`.

## Pokretanje na Linuxu

Potrebni su Node.js 20 ili noviji, npm i PostgreSQL. Provjeri verziju Node.js
naredbom `node --version`; instaliraj podržanu verziju ako je starija.

Na Ubuntu/Debian sustavu instaliraj PostgreSQL:

```bash
sudo apt update
sudo apt install postgresql
```

Izradi lokalnog korisnika baze i bazu:

```bash
sudo -u postgres psql
```

U PostgreSQL konzoli upiši (zamijeni primjer lozinke vlastitom lokalnom):

```sql
CREATE USER web2_user WITH PASSWORD 'promijeni-ovu-lozinku';
CREATE DATABASE web2_security_lab OWNER web2_user;
\q
```

Iz korijenske mape projekta kopiraj predložak i uredi postavke:

```bash
cp .env.example .env
nano .env
```

U `.env` postavi `DB_USER=web2_user` i `DB_PASSWORD` na istu lozinku koju si
postavio pri izradi korisnika. Zatim iz mape projekta instaliraj, testiraj i
pokreni aplikaciju:

```bash
npm install
npm test
npm start
```

Otvori `http://127.0.0.1:3000`. Nemoj dodavati `.env` u Git repozitorij.

Pri prvom pokretanju aplikacija stvara tablicu i dva sintetička korisnika.
Zaštićeni način rada je početni. Testni računi koriste zaporku `demo123`:

- `demo-admin` — administratorska uloga
- `demo-user` — korisnička uloga

## Demonstracije

- **SQL Injection:** uključi prekidač i pokreni tautološki test. U ranjivom
  demo načinu pretraga vraća sve demo račune; u zaštićenom načinu isti unos
  tretira se kao običan tekst. Unos se ne izvršava kao SQL; demonstracija
  prepoznaje samo fiksnu sintetičku tautologiju, a sve SQL upite šalje
  parametrizirano.
- **Pogađanje zaporki:** isključi ograničenje pokušaja i isprobaj testni login.
  Zaštićeni način blokira prijavu nakon tri pogrešna pokušaja na 30 sekundi;
  gumb za reset služi samo za ponavljanje lokalne demonstracije.

Odjeljak **Loša autentifikacija** uvijek provjerava zaporku; prekidači
upravljaju ograničenjem pokušaja i porukama o pogrešci. Zaštićeni načini su
početni. Postavke se vraćaju na početno stanje pri ponovnom pokretanju
poslužitelja.
