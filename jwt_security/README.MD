## Resumo do fluxo

- O usuário envia credenciais para /auth/login
- O AuthController autentica o usuário usando o AuthenticationManager
- Se autenticado com sucesso, gera um token JWT usando o JWTService
- O token é retornado ao usuário
- Para solicitações subsequentes, o usuário envia o token no cabeçalho Authorization
- O JWTFilter valida o token usando o JWTValidator e configura o SecurityContext

## Mudança para evitar dependências cíclicas
Esta implementação segue os princípios modernos de desenvolvimento com Spring Security e JWT, utilizando a versão mais recente da biblioteca JJWT (0.12.6) e aproveitando os recursos nativos oferecidos.

Essa separação resolve o problema porque:

- JwtConfig define os beans JWTService e JWTValidator
- SecurityConfig injeta JWTValidator (não cria ele)
- AuthController injeta JWTService (não cria ele)

Não há mais dependências cíclicas porque os componentes agora dependem de uma terceira classe (JwtConfig) que fornece os beans necessários.
Isso segue o princípio de design "Injeção de Dependência" e "Separação de Responsabilidades", tornando seu código mais modular e evitando ciclos de dependência.

## Testando os endpoints com Postman

1. **Criação do usuário**:
   - Método: `POST`
   - Headers:
     - `Content-Type: application/json`
   - URL: `http://localhost:8080/users`
   - Corpo da requisição (JSON):
     ```json
     {
       "username": "admin",
       "password": "admin",
       "roles": ["ROLE_ADMIN"]
     }
     ```

   - **Observação**: O usuário é criado com a senha criptografada.
2. **Autenticação**:
   - Método: `POST`
   - Headers:
     - `Content-Type: application/json`
   - URL: `http://localhost:8080/auth`
   - Corpo da requisição (JSON):
     ```json
     {
       "username": "admin",
       "password": "admin"
     }
     ```
     
    - **Resposta**: O token JWT é retornado no corpo da resposta.

      3. **Acesso a um endpoint protegido**:
         - Método: `GET`
         - Headers:
           - `Authorization: Bearer {token}`
           - **Observação**: Substitua `{token}` pelo token JWT obtido na etapa anterior.
         - URL: `http://localhost:8080/users`
         - **Resposta**: A lista de usuários é retornada se o token for válido.
         ```json
           {
             "id": 1,
             "username": "admin",
             "password": "$2a$10$.nALxY4AQn2aMo3Mx7RTLe20c2F9B85iAE0OVWXO9vZz8MufIup0C"
             "roles": [
                      "USERS",
                      "MANAGERS"
                  ],
           }
           ```
   