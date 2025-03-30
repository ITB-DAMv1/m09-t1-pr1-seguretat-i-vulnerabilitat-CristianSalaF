[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/S9WTUTwx)

# T1-PR1: Cristian Sala

## 1. L’organització [OWASP Foundation](https://owasp.org/Top10/es/) va actualitzar en 2021 el seu Top 10 de vulnerabilitats més trobades en aplicacions web.
### a. Escull 3 vulnerabilitats d’aquesta llista i descriu-les. Escriu l’impacte que tenen a la seguretat i quins danys pot arribar a fer un atac en aquesta vulnerabilitat. Enumera diferents mesures i tècniques per poder evitar-les. 

Vulnerabilitats escollides:

- 1. Broken Access Control/Trencament del control d'accés (A01:2021) 
  - Descripció: Consisteix en falles en els mecanismes de control d'accés que permeten als atacants accedir, 
      modificar o eliminar dades sense autorització. Ocorre quan les aplicacions no verifiquen correctament els 
      permisos d'usuari abans de permetre l'accés a funcionalitats o dades.
  - Impacte: Els atacants poden accedir a comptes d'altres usuaris, veure dades sensibles, modificar permisos, 
      i en casos greus, assumir control complet del sistema. Això pot provocar robatori d'informació confidencial, 
      modificació no autoritzada de dades i comprometre la integritat del sistema.

    Mesures preventives:
      
        Implementar control d'accés basat en rols (RBAC)
        Denegar l'accés per defecte (principi del mínim privilegi)
        Validar permisos a nivell de servidor, no només a la interfície
        Implementar límits de ràtio per evitar força bruta
        Invalidar sessions al logout i després d'un temps d'inactivitat
        Fer tests d'intrussió regularment
- 2. Cryptographic Failures/Errors criptogràfics (A02:2021)
   - Descripció: Aquesta vulnerabilitat (abans coneguda com "Sensitive Data Exposure") es refereix a les falles 
     en la implementació de mecanismes criptogràfics que protegeixen dades sensibles. Inclou l'ús d'algoritmes febles, 
     mala gestió de claus o no xifrar dades en trànsit o en repòs.

    - Impacte: Permet als atacants accedir a informació sensible com credencials, dades personals, dades financeres 
      o informació mèdica. Pot resultar en robatori d'identitat, frau financer, violacions de privacitat i 
      incompliment de normatives com GDPR.

     Mesures preventives:

         Utilitzar algoritmes criptogràfics estàndard i actualitzats
         Implementar HTTPS en tota l'aplicació
         Emmagatzemar només les dades necessàries (minimització)
         Xifrar totes les dades sensibles en repòs
         No emmagatzemar contrasenyes en text pla, utilitzar hash amb salt
         Mantenir actualitzades les biblioteques criptogràfiques
         Implementar una gestió segura de claus
- 3. Injection/Injecció (A03:2021)
      - Descripció: Les vulnerabilitats d'injecció (SQL, NoSQL, LDAP, OS, etc.) ocorren quan dades no confiables són 
        enviades a un intèrpret com a part d'una comanda o consulta. Les dades hostils poden enganyar l'intèrpret 
        per executar comandes no desitjades o accedir a dades sense autorització.

    - Impacte: Permet als atacants executar comandes no autoritzades, obtenir, modificar o eliminar dades, 
      i en alguns casos, aconseguir control total del servidor. Pot portar a pèrdua de dades, 
      compromisos de confidencialitat i integritat, i fins i tot la presa de control total del sistema.

    Mesures preventives:

        Utilitzar consultes parametritzades (prepared statements)
        Usar ORM (Object-Relational Mapping) com Entity Framework
        Validar i netejar totes les entrades d'usuari
        Implementar llistes blanques per validació d'entrada
        Aplicar el principi del mínim privilegi en comptes de base de dades
        Utilitzar procediments emmagatzemats
        Implementar WAF (Web Application Firewall)
        Fer tests de penetració regularment

## 2. Obre el següent enllaç [sql inseckten](https://www.sql-insekten.de/) i realitza un mínim de 7 nivells fent servir tècniques d’injecció SQL.
- a. Copia cada una de les sentències SQL resultant que has realitzat a cada nivell i comenta que has aconseguit.
  1. Nivell 1: al comentar la part del "AND" mitjançant la injecció, permet entrar sense saber la contrasenya del usuari. 
  
  `SELECT username FROM users WHERE username ='jane' --' AND password ='d41d8cd98f00b204e9800998ecf8427e';`
  2. Nivell 2: 
  
    `SELECT username FROM users WHERE username =''; DROP TABLE users; --' AND password ='d41d8cd98f00b204e9800998ecf8427e';`
  3. Nivell 3: Força un retorn de true amb una injecció del `OR 1=1`, podent accedir sense usuari
  
    `SELECT username FROM users WHERE username = '' OR 1=1 --' AND password ='d41d8cd98f00b204e9800998ecf8427e';`
  4. Nivell 4: Igual que el exercici 3 però es limiten els resultats a 1, ja que "ho han arreglat".
  
    `SELECT username FROM users WHERE username ='' OR 1=1 limit 1 --' AND password ='d41d8cd98f00b204e9800998ecf8427e';`
  5. Nivell 5: Fent servir Union, es pot unir una segona consulta i mostrar dades adicionals, com per exemple la taula amb usuaris i contrasenyes.
    
    `SELECT product_id, brand, size, price FROM shoes WHERE brand='' UNION SELECT username, password, null, null FROM users --';`
    Això menciona les [Rainbow tables](http://project-rainbowcrack.com/table.htm), 
    les quals permeten desencriptar dades en base a datasets pre-generats.
  6. Nivell 6: Aquesta injecció retornarà el salari de Greta Maria com si fos un nom d'usuari en els resultats aprofitant-se del alias de columnes.
    
    `SELECT username FROM users WHERE username = '' UNION SELECT s.salary AS username FROM staff s WHERE s.firstname = 'Greta Maria' --' AND password ='d41d8cd98f00b204e9800998ecf8427e';`
  7. Nivell 7:
    
    `SELECT product_id, brand, size, price FROM shoes WHERE brand='' UNION SELECT name, email, salary, employed_since FROM staff --'`

- b. Enumera i raona diferents formes que pot evitar un atac per SQL injection en projectes fets amb Razor Pages i Entity Framework.
  1. Usar Entity Framework Core adequadament: EF Core utilitza per defecte consultes parametritzades que eviten SQL Injection. 
  Cal evitar construir consultes amb concatenació de cadenes. 
  2. Implementar LINQ en lloc de SQL directe: Utilitzar LINQ per consultar la base de dades, ja que tradueix les consultes a paràmetres segurs.
    
         var resultats = _context.Usuaris.Where(u => u.Username == username);
  
  3. Evitar l'ús de FromSql sense paràmetres: Si s'han d'utilitzar consultes SQL directes, assegurar-se d'utilitzar parametrització: 
  
         _context.Usuaris.FromSqlRaw("SELECT * FROM Usuaris WHERE Username = {0}", username);
  
  4. Validació d'entrades: Implementar validació de model a les classes Razor Pages:
  
         [Required]
         [StringLength(50, MinimumLength = 3)]
         [RegularExpression(@"^[A-Za-z0-9_]+$")]
         public string Username { get; set; }

  5. Utilitzar stored procedures: Per operacions complexes, utilitzar procediments emmagatzemats que són menys vulnerables a la injecció SQL.
  6. Implementar principi de mínim privilegi: Utilitzar un usuari de base de dades amb permisos limitats per l'aplicació web.
  7. Filtrar i sanititzar entrades d'usuari: Utilitzar biblioteques com HtmlSanitizer per netejar les entrades d'usuari abans de processar-les.
  8. Implementar patró Repository: Encapsular totes les operacions de dades en repositoris, 
  facilitant la revisió i auditoria del codi d'accés a dades.

## 3. L’empresa a la qual treballes desenvoluparà una aplicació web de venda d’obres d’art. Els artistes registren les seves obres amb fotografies, títol, descripció i preu.  Els clients poden comprar les obres i poden escriure ressenyes públiques dels artistes a qui han comprat. Tant clients com artistes han d’estar registrats. L’aplicació guarda nom, cognoms, adreça completa, dni i telèfon. En el cas dels artistes guarda les dades bancaries per fer els pagaments. Hi ha un tipus d’usuari Acount Manager que s’encarrega de verificar als nous artistes. Un cop aprovats poden publicar i vendre les seves obres.

Ara es vol aplicar aplicant els principis  de seguretat per tal de garantir el servei i la integritat de les dades. 
T’han encarregat l'elaboració de part de les polítiques de seguretat. Elabora els següents apartats:

- a. Definició del control d’accés: enumera els rols  i quin accés a dades tenen cada rol.
  - Rol: Visitant (no registrat)
    - Accés: Visualització d'obres d'art públiques, perfils bàsics d'artistes i ressenyes
    - Dades accessibles: Informació pública d'obres (títol, imatges, descripció, preu), nom artístic i biografia pública dels artistes
  - Rol: Client
    - Accés: Tot el que pot veure un visitant, més capacitat de compra d'obres i escriure ressenyes
    - Dades accessibles: Les mateixes que un visitant, més historial de compres pròpies, gestió del perfil personal i ressenyes escrites
  - Rol: Artista
    - Accés: Publicació, edició i eliminació de les seves pròpies obres, visualització de vendes pròpies
    - Dades accessibles: Gestió del perfil propi, dades de vendes de les seves obres, informació sobre els clients 
    que han comprat (limitat a dades necessàries per l'enviament)
  - Rol: Account Manager
    - Accés: Verificació d'artistes, gestió bàsica d'usuaris, resolució d'incidències
    - Dades accessibles: Dades de verificació d'artistes, dades bàsiques de clients i artistes (sense accés a dades bancàries completes), 
    historial de transaccions per resoldre disputes
  - Rol: Administrador
    - Accés: Gestió completa del sistema, auditoria, configuració global
    - Dades accessibles: Totes les dades del sistema excepte contrasenyes i dades bancàries completes 
    (només visualització parcial per verificacions)
    
- b. Definició de la política de contrasenyes: normes de creació, d’ús i canvi de contrasenyes. Raona si són necessàries diferents polítiques segons el perfil d’usuari.
  - Normes de creació:
    - Mínim 12 caràcters per a tots els usuaris
    - Combinació obligatòria de majúscules, minúscules, números i caràcters especials
    - No permetre contrasenyes comunes o compromeses (validar contra bases de dades de contrasenyes filtrades)
    - No permetre informació personal a la contrasenya (nom, cognom, email, etc.)
    - Implementar verificació de força de contrasenya en temps real
    - (alternativa) no fer servir contrasenya sino un token de una clau de seguretat o certificat
  - Normes d'ús:
    - Bloqueig temporal després de 5 intents fallits (10 minuts)
    - Implementació d'autenticació de dos factors (2FA) obligatòria per a artistes i account managers, opcional per a clients
    - Sessions amb expiració automàtica després de 30 minuts d'inactivitat
    - Tancament de sessió automàtic en múltiples dispositius simultanis per al mateix usuari
  - Política de canvi:
    - Canvi obligatori cada 90 dies per a account managers i administradors
    - Canvi obligatori cada 180 dies per a artistes
    - Canvi recomanat però no obligatori per a clients
    - No permetre reutilització de les últimes 5 contrasenyes (millor si fós basat en temps, no només en el nombre de contrasenyes)
    - Notificació per email de canvis de contrasenya o intents d'accés sospitosos
  - Diferències segons perfil - És necessari tenir polítiques diferents segons el perfil d'usuari, ja que:
    - Els account managers i administradors tenen accés a dades més sensibles i haurien de tenir requisits més estrictes
    - Els artistes gestionen informació financera i haurien de tenir un nivell de seguretat mig-alt
    - Els clients poden tenir requisits més flexibles per millorar l'experiència d'usuari i evitar fricció en el procés de compra
  - Observacions adicionals
    - Una forma de fer-se passar per un usuari es robant-li les dades del navegador que contenen les sessions guardades, 
    no permetre això, o fer que expiri en un termini molt curt, o bè contrastar el id de sessió amb el 
    identificador únic del navegador o dispositiu per validar-ho.
  
- c. Avaluació de la informació: determina quin valor tenen les dades que treballa l'aplicació. Determina com tractar les dades més sensibles. Quines dades encriptaries?
  - Valor de les dades:
    - Dades d'alt valor: Informació bancària dels artistes, dades personals completes (DNI, adreça), credencials d'accés, historial de transaccions
    - Dades de valor mitjà: Informació de contacte, historial de compres, propietat intel·lectual de les obres
    - Dades de baix valor: Informació pública sobre les obres, ressenyes públiques, noms artístics
  - Tractament de dades sensibles:
    - Implementar el principi de minimització de dades (recollir només el necessari)
    - Aplicar tècniques d'anonimització o pseudonimització quan sigui possible
    - Aplicar accés basat en necessitat de conèixer (need-to-know basis)
    - Implementar registres d'auditoria per a tot accés a dades sensibles
    - Complir amb RGPD i altres normatives de protecció de dades aplicables
  - Dades a encriptar:
    - Contrasenyes (hash amb salt, no encriptació reversible)
    - Dades bancàries complertes dels artistes
    - DNI i altres documents d'identitat
    - Adreces completes
    - Historial complet de transaccions
    - Comunicacions privades entre usuaris
    - Credencials d'accés i tokens d'autenticació
    - Còpies de seguretat de la base de dades

## 4. En el control d’accessos, existeixen mètodes d’autenticació basats en tokens. Defineix l’autenticació basada en tokens. Quins tipus hi ha? Com funciona mitjançant la web? Cerca llibreries .Net que ens poden ajudar a implementar autenticació amb tokens.
L'autenticació basada en tokens és un mètode d'autenticació on el servidor genera un token després que l'usuari 
s'ha autenticat correctament. Aquest token s'utilitza per a les subsegüents peticions a l'API sense necessitat d'enviar 
les credencials novament.

1. Tipus d'autenticació basada en tokens:
   1. JSON Web Tokens (JWT): Format estàndard obert (RFC 7519) que utilitza JSON per transmetre informació de forma segura entre parts. Consisteix en tres parts: header, payload i signature.
   2. OAuth 2.0: Protocol d'autorització que permet a aplicacions terceres obtenir accés limitat a un servei en nom de l'usuari. Utilitza tokens d'accés i de refresc.
   3. OpenID Connect: Capa d'identitat construïda sobre OAuth 2.0 que permet verificar la identitat de l'usuari i obtenir informació bàsica del perfil.
   4. SAML (Security Assertion Markup Language): Protocol basat en XML utilitzat per SSO (Single Sign-On), més comú en entorns empresarials.
   5. Tokens simples: Tokens alfanumèrics generats aleatòriament sense estructura interna definida, que s'emmagatzemen al servidor.
2. Funcionament en la web:
   1. Autenticació inicial: L'usuari proporciona credencials vàlides (usuari/contrasenya).
   2. Generació del token: El servidor verifica les credencials i genera un token signat que conté informació com l'ID d'usuari i els permisos.
   3. Emmagatzematge del token: El client (navegador) emmagatzema el token, generalment en localStorage, sessionStorage o cookies.
   4. Peticions autenticades: El client inclou el token a la capçalera (normalment com a "Authorization: Bearer [token]") en cada petició a l'API.
   5. Verificació del token: El servidor verifica la validesa i signatura del token abans de processar la petició.
   6. Renovació de tokens: S'implementen mecanismes de refresh token per renovar els tokens d'accés sense demanar novament les credencials.
3. Llibreries .NET per implementar autenticació amb tokens:
   1. Microsoft.AspNetCore.Authentication.JwtBearer: Middleware oficial de Microsoft per autenticació JWT en ASP.NET Core.
   2. System.IdentityModel.Tokens.Jwt: Biblioteca per crear i validar tokens JWT.
   3. IdentityServer4: Framework d'autenticació complet que implementa OAuth 2.0 i OpenID Connect.
   4. Microsoft Identity Web: Biblioteca de Microsoft per integrar aplicacions amb Microsoft Identity Platform (Azure AD).
   5. JWT.NET: Biblioteca lleugera per codificar i descodificar tokens JWT.
   6. Duende IdentityServer: Successor comercial d'IdentityServer4, amb suport professional.
   7. Microsoft.AspNetCore.Authentication.OAuth: Per implementar autenticació OAuth 2.0.
   8. Auth0.NET: Client oficial per integració amb el servei Auth0.

## 5. Crea un projecte de consola amb un menú amb tres opcions:
- a. Registre: l’usuari ha d’introduir username i una password. De la combinació dels dos camps guarda en memòria directament l'encriptació. Utilitza l’encriptació de hash SHA256. Mostra per pantalla el resultat.
- b. Verificació de dades: usuari ha de tornar a introduir les dades el programa mostra per pantalla si les dades són correctes.
- c. Encriptació i desencriptació amb RSA. L’usuari entrarà un text per consola. A continuació mostra el text encriptat i en la següent línia el text desencriptat. L’algoritme de RSA necessita una clau pública per encriptar i una clau privada per desencriptar. No cal guardar-les en memòria persistent.

Per realitzar aquest exercici utilitza la llibreria `System.Security.Cryptography`.


## 6. 
> Foundation OWASP (2021), OWASP Top Ten 2021, OWASP Foundation. 
> Recuperat el 29 març 2025 de https://owasp.org/Top10/

> Microsoft (2023), ASP.NET Core Security Documentation, Microsoft Docs. 
> Recuperat el 28 març 2025 de https://docs.microsoft.com/aspnet/core/security/

> HACKERCOOL, Complete guide to cryptography.
> Recuperat el 28 de març de 2025 https://www.hackercoolmagazine.com/complete-guide-to-cryptography

> INFOSEC TRAIN (2023), Web Application Basics | OWASP Introduction | Exploiting Vulnerabilities of Web Application.
> Recuperat el 28 de març de 2025 de https://www.youtube.com/watch?v=Pk4IO0NcTw0

> Ajay Monga, Top 10 Common Web Application Vulnerabilities and Best Practices for Prevention.
> Recuperat el 28 de març de 2025 de https://medium.com/@ajay.monga73/top-10-common-web-application-vulnerabilities-and-best-practices-for-prevention-430fc675f273

> Microsoft (2025), System.Security.Cryptography Espacio de nombres, Microsoft Learn.
> Recuperat el 29 de març de https://learn.microsoft.com/es-es/dotnet/api/system.security.cryptography?view=net-9.0

> Microsoft (2025), RSACryptoServiceProvider.Encrypt Método, Microsoft Learn.
> Recuperat el 29 de març de https://learn.microsoft.com/es-es/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.encrypt?view=net-9.0

> Crypto Stackexchange (2024), Why does adding PKCS#1 v1.5 padding make RSA encryption non-deterministic?
> Recuperat el 29 de març de https://crypto.stackexchange.com/questions/66521/why-does-adding-pkcs1-v1-5-padding-make-rsa-encryption-non-deterministic 