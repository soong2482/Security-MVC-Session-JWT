# Security Session+JWT

기초적인 Spring Security를 사용한 MVC 프로젝트입니다. 이 프로젝트에서는 회원가입(SignUp), 로그인(Login), 로그아웃(Logout), 그리고 Role 권한에 따른 API 요청을 구현합니다

## 부가적인 설명
세션과 JWT의 결합을 하기위해 많은 고민을 하였습니다. 각 기능의 장점을 살리기위하여 저는

이렇게 생각하였습니다. 세션의 서버에서의 안정적인 사용자 관리와 저장, JWT의 무상태 인증 및 보안

을 합하여 보안에 민감한 api의 세션,jwt 이중인증을 구현하였습니다. 그리고 보안에 민감하지

않은 api요청들은 로그인이 유지되고있는 jwt인증만으로 받아올수 있게 하여 성능을 향상시켰습니다.

리프레시 토큰을 이용하여 지속적인 인증을 하게 하였고 토큰이 탈취당하여도 세션을 통하여 관리할수 있다는 장점이 제일 좋다고 생각합니다.


## 1. 환경 설정(BuildGradle)
- Spring Boot Starter Security
- Spring Boot Starter Web
- MyBatis Spring Boot Starter
- Spring Boot Starter Logging
- Lombok
- MariaDB JDBC 드라이버
- MyBatis
- Spring Boot Starter Data Redis
- Spring Session Data Redis
- Spring Boot Starter Mail 
- JsonWebToken::jjwt
### DB구성(Role의 권한 확장성을 위해 테이블 세분화)
![image](https://github.com/soong2482/SecurityMVC/assets/97108130/78fb2277-47c0-416b-83a0-ba960b7efdff)

## 2.메서드 소개(SignUP)


## 회원가입
https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SignUpInfo/Service/SignUpService.java
https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/UserInfo/Service/UserDetailsService.java

#### 중복검증(아이디중복검증)
Post요청으로 
```json
{
    "UserName" : "soong2482"
}
```
##### 처리 과정:
MyBatis를 통해 UserDetails -> userMapper 에서 아이디를 조회하고, Optional<String> 형태로 반환된 데이터를 검증합니다.
여기서 검증할 데이터는 아이디의 중복 여부입니다. 존재하면 이미 사용 중인 아이디로 간주하고, 존재하지 않으면 사용 가능한 아이디로 처리합니다.





#### 이메일 검증(이메일중복검증)
Post요청으로 
```json
{
    "Email" : "soong3899@naver.com"
}
```
##### 처리 과정:
MyBatis를 통해  UserDetails -> userMapper에서 이메일을 조회하고, Optional<String> 형태로 반환된 데이터를 검증합니다.
여기서 검증할 데이터는 이메일의 중복 여부입니다. 존재하면 이미 사용 중인 이메일로 간주하고, 존재하지 않으면 사용 가능한 이메일로 처리합니다.


#### 이메일 검증(이메일 유효코드전송)
Post요청으로
```json
{
    "Email" :"soong3899@naver.com"
}
```
##### 처리 과정:
emailService.generateAuthCode() 를 통하여 랜덤코드를 만들고
redisTemplate.opsForValue().set("email_verification:" + email, authCode, 3000, TimeUnit.SECONDS); redis에 이메일주소(키)와 함께 랜덤코드(밸류)를 저장합니다.
emailService.sendEmail(email, subject, body); 코드를 통하여 requestbody에 있던 이메일의 주소로 이메일을 전송합니다.


#### 이메일 검증(이메일 유효코드확인)
Post요청으로
```json
{
    "Email" : "soong3899@naver.com",
    "EmailCode": "185942"
}
```
##### 처리 과정:
String storedAuthCode = redisTemplate.opsForValue().get("email_verification:" + email); 를 통하여 redis에서 이메일주소(키)에 저장되어 있던  랜덤코드(밸류)를 꺼내옵니다.
*redis에 있는 저장되어있는 emailcode는 아직 삭제하지 않습니다(회원가입때 한번 더 검증).
requestbody에 있던 코드와 equals일시 STATUS 200을 반환합니다.







#### 회원가입(최종 검증)
Post요청으로
```json
{
  "username": "soong2482",
  "password": "RandomPass",
  "email": "soong3899@naver.com",
  "emailCode":"666643"
}
```

##### 처리 과정:
다시 한번더 mybatis를통해 아이디 중복검증을 수행하며 성공시 바로 이후에 이메일 검증을 redis에 저장되어있던 코드를 꺼내와 한번 더 수행합니다.

https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SignUpInfo/Domain/SignUp.java

이후에 SignUp도메인에 setAuthority("ROLE_USER"); setPassword(passwordEncoder.encode(signUp.getPassword()));  signUp.setEnabled(true);
사용된 이메일 키값과 이메일 코드는 redis에서 폐기 합니다.
를 통하여 역할, 비밀번호 암호화,접근 허용 체크를 해주고mybatis를 통하여 각각의 DB Table에 저장합니다.








## 로그인

https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/LoginInfo/Service/LoginService.java

Post요청으로
```json
{
    "username" : "soong2482",
    "password": "RandomPass"
}
```

### 처리 과정:

 -LoginRequest 로그인

1.클라이언트로부터 받은 username과 password를 사용하여 UsernamePasswordAuthenticationToken 객체를 생성합니다.

2.authenticationManager를 사용하여 인증 요청을 처리합니다.

3.인증이 성공하면 SecurityContextHolder에 인증 정보를 저장합니다.

4.HttpSession 객체를 생성하여 세션을 활성화합니다.

5.세션에 SPRING_SECURITY_CONTEXT와 username, roles 정보를 저장합니다.

6.세션의 유효기간을 액세스 토큰의 유효 기간(ACCESS_TOKEN_EXPIRATION)으로 설정합니다(세션은 redis에서 관리합니다).

7.사용자 이름과 역할 정보를 기반으로 액세스 토큰을 생성합니다(여기에 세션 ID가 추가됩니다).

8.사용자 이름을 기반으로 리프레시 토큰을 생성합니다(redis에 사용자 이름 기반으로 저장됩니다).

9.리프레시 토큰과 액세스 토큰을 쿠키로 클라이언트로 setCookie합니다.


## CustomAuthenticationProvider
https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SpringSecurity/SecurityConfig.java

https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SpringSecurity/CustomAuthenticationProvider/CustomAuthenticationProvider.java
Custom으로 직접 인증 Provider를 만들어 사용합니다.

### 처리 과정:
SecurityConfig에 Bean으로 AuthenticationManager에 CustomProvider를 추가해놓은 상태에서
authenticationManager.authenticate(authenticationRequest); 형태로 authenticate요청이 오면 CustomProvider로넘어가서 인증을 수행하게됩니다.

### Role권한 관련 인증일시(null Credentials)
Role권한으로 인한 접근권한api요청시 password가 없는상태로 세션정보가 넘어오기 때문에 먼저 getCredentials을통하여 검증합니다.
```code
       if (authentication.getCredentials() == null) {
            User user = (User) authentication.getPrincipal();
            return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
        }
```
authentication.getPrincipal()을 통해 사용자 정보를 가져옵니다.
사용자 정보를 사용해 새로운 UsernamePasswordAuthenticationToken 객체를 생성합니다.

### 일반 로그인 관련 인증일시

authentication 객체에서 사용자 이름과 자격 증명(비밀번호)을 가져옵니다.
UserDetailsService를 통해 사용자 정보를 조회합니다. 
UserMapper를 통해 조회된 사용자 정보로 아이디와 비밀번호를 검증하고, 사용자가 활성화(Enabled) 상태인지 확인합니다.
검증에 성공하면
```code
  User user = userDetailsService.findByDetailUser(username).get();
            return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
```
를 통하여 새로운 UsernamePasswordAuthenticationToken 객체를 생성하여 사용자 정보와 권한을 포함시킵니다.



# 로그인을 제외한 일반 데이터의 접근

로그인을 제외한 일반 데이터의 접근 ex)로그인 이후 home 화면 접근
로그인 이후에 accesstoken과 rereshtoken, session이 발급되는데 여기서 session은 클라이언트에서 저장시키지 않고
accesstoken와 refreshtoken만 저장시킵니다. +둘다 쿠키에 저장됩니다.

여기서 권한이 필요 없는 일반적인 접근이라면 ex) /Security/Data/** 
을 jwt필터에 추가하여 jwt 검증만 수행하게합니다. 

```code
    String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
            if (accessToken == null) {
                throw new AuthenticationException("Access token is missing") {};
            }

            if (!jwtService.validateToken(accessToken)) {
                throw new AuthenticationException("Access token is not valid") {};
            }

            Claims claims = jwtService.getClaimsFromToken(accessToken);
            String username = claims.getSubject();
             List<String> roles = (List<String>) claims.get("roles", List.class);

            if (username == null) {
                throw new AuthenticationException("User is not authenticated (username is not valid)") {};
            }

            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

```

이러한 과정을 통해서 session에 접근하는것이 아닌 jwt로만 인증을 수행하므로 효율성이 증가하게됩니다. 





# 로그인 이후 Role에 따른 접근 필터

https://github.com/soong2482/Security-MVC-Session-JWT/tree/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SpringSecurity/CustomAuthenticationFilter
현재는 Admin과 SuperAdmin,User 만 구현해 놓은 상태입니다. 확장은 DB에 역할을 추가하고 메서드를 조금만 수정하면 역할을 확장할 수 있습니다.

#### CustomAdminAuthenticationFilter extends AbstractAuthenticationProcessingFilter
#### CustomSuperAdminAuthenticationFilter extends AbstartAuthenticationProcessingFilter
##### 처리 과정:

"/Security/Admin/**"로 오는 모든 요청을 가로채서 필터를 통과시키게 합니다.
```code
 String accessToken = refreshTokenService.getAccessTokenFromCookies(request);
         if (accessToken == null) {
            throw new AuthenticationException("Access token is missing") {};
        }
        if(!jwtService.validateToken(accessToken)){
            throw new AuthenticationException("User is not authenticated(Token is not valid)") {};
        }
        List<?> authoritiesObj = (List<?>) jwtService.getRolesFromToken(accessToken);
        if (authoritiesObj == null) {
            throw new AuthenticationException("No roles found in session") {};
        }
        String sessionId = jwtService.getSessionIdFromToken(accessToken);
        if (sessionId == null || !sessionService.isSessionValid(sessionId)) {
            throw new CustomExceptions.AuthenticationFailedException("User is not authenticated(Session is not valid)");
        }
```
코드를 통하여 먼저 세션의 유효성과 토큰의 유효성을 검사합니다. +동시에 역할의 유호성도 검사합니다.

```code
List<GrantedAuthority> authorities = new ArrayList<>();
        for (Object authorityObj : authoritiesObj) {
            if (authorityObj instanceof GrantedAuthority) {
                authorities.add((GrantedAuthority) authorityObj);
            } else if (authorityObj instanceof String) {
                authorities.add(new SimpleGrantedAuthority((String) authorityObj));
            } else {
                throw new AuthenticationException("Invalid authority type in session") {};
            }
        }
```
authorities에 세션에서 가져온 권한 리스트를 반복하여 
```code
if (authorityObj instanceof GrantedAuthority):
```
현재 권한 객체가 GrantedAuthority 타입인지 확인하고
```code
authorities.add((GrantedAuthority) authorityObj): GrantedAuthority 타입인 경우 리스트에 추가합니다
```
```code
else if (authorityObj instanceof String): 현재 권한 객체가 String 타입인지 확인하고.
```
```code
authorities.add(new SimpleGrantedAuthority((String) authorityObj)): String 타입인 경우 SimpleGrantedAuthority 객체로 변환하여 리스트에 추가합니다.
```
이후 권한리스트를 반복하여 ADMIN의 권한이 있을경우 새로운 UsernamePasswordAuthenticationToken 객체를 생성하여 사용자 이름과 권한을 포함시킵니다.
세션에서 가져온 데이터임으로 password는 비어있습니다. 이후 authenticate에서 처리됩니다.

filter를 참조하여 
```code
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
        chain.doFilter(request, response);
    }
```
https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SpringSecurity/CustomHandler/CustomSuccessHandler.java
    인증 성공시 handler를 호출후 필터체인을 계속해서 진행시킵니다.
   ```code
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
```
https://github.com/soong2482/Security-MVC-Session-JWT/blob/Session%2BJWT_SNAPSHOT/src/main/java/com/spring/SecurityMVC/SpringSecurity/CustomHandler/CustomFailedHandler.java
  인증성공과 실패시 사용할 핸들러들을 설정합니다.
```code
@Slf4j
public class CustomFailedHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        log.warn("Authentication failed for user: {} with exception: {}", session.getAttribute("username"), exception.getMessage());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    } 
} 접근권한에 맞지 않는 정보에 접근시 그 유저의 아이디와 접근할려했던 URI를 log에남깁니다.
```
```code
@Slf4j
public class CustomSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("Authentication Success: User {} has been authenticated when accessing {} successfully.", authentication.getName(),request.getRequestURI());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
```
인증성공시 SecurityContext에 저장합니다. 그리고 접근한 유저의 아이디와 접근하려하였던 URI를 로그로 남기고 이후의 처리를 이어서 합니다. 






    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomAdminAuthenticationFilter customAdminAuthenticationFilter, CustomSuperAdminAuthenticationFilter customSuperAdminAuthenticationFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .httpBasic(httpBasic -> httpBasic
                        .authenticationEntryPoint((request, response, authException) -> {
                            customFailedHandler().onAuthenticationFailure(request, response, authException);
                        })
                )
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().permitAll()
                )
                .formLogin(formLogin -> formLogin.disable());

        http.addFilterBefore(customAuthenticationJwtFilter,UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customUserAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customAdminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(customSuperAdminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
SecurityFilterChain을통해 http.addBefore로 권한이 낮은 순서대로 필터를 거칩니다. 



# 개발하다 접근한 문제들

처음 문제는 권한을 여러개로 처리할떄 처음으로 마주하였습니다.
권한을 여러개로 처리하기위해 어떤 방법이 있을지 찾다 Mapper에서 List<String>형태로 리턴받아     
authentication.getPrincipal에 맞는 형태로 저장하기위하여 
직접 권한을 하나하나 추가하여 제작하는 방법 선택하였습니다. 

실제로 Authentication의 메서드중 권한 메서드는
	Collection<? extends GrantedAuthority> getAuthorities();
이렇게 구성되어있었습니다.

https://github.com/soong2482/SecurityMVC/blob/main/src/main/java/com/spring/SecurityMVC/UserInfo/Domain/User.java

public void setAuthorities(List<String> roles) {
        for (String role : roles) {
            if (role != null && !role.isEmpty()) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
        }
    }

두번째는 UsernamePasswordAuthenticationToken의 대한 문제였습니다.
꼭 이 형식을 맞춰서 해야하나 싶었지만 기본적으로 제공하는 사용자 이름과 비밀번호 기반의 인증 메커니즘을 활용하기 위해서 그대로 Custom하지 않고 사용하였습니다. 

이 프로젝트는 Dawon/BackEnd라는 프로젝트를 진행하다가 Security에 대한 지식이 부족한 것 같아서 시작하였습니다.

//JWT 추가 이후

세션과 JWT의 장점들만 꺼내어 어떻게 결합해야하나가 제일 걱정이였습니다.

세션을 이용하여 사용자의 상태를 서버에서 직접적으로 관리할 수 있게 하고

JWT의 무상태 인증을 통하여 역할접근 api가아닌 일반적인 api요청들은 효율성있게 받아오도록 하였습니다.

세션과 jwt의 이중보안으로 보안성은 강화되었습니다.

리프레시 토큰을 이용하여 지속적인 인증을 하게 하였고 토큰이 탈취당하여도 세션을 통하여 관리할수 있다는 장점이 제일 좋다고 생각합니다.



# +개선할 점
1.보안인증에서 로그인은 성공하였지만 session으로의 로그인중 검증이 부족하여 고민이 있습니다. 추후에 수정해서 추가하도록 하겠습니다 () 

2.세션이 있는 상태에서 세션로그인이 아닌 loginrequest로 인한 로그인시 전 로그인 세션을 폐기시키고 새로운 세션을 만들게끔 하려고합니다. +로그 남기기()

3.된다면 좋겠지만 이메일을 전송할 때 유효하지않은 이메일로 확인코드를 전송시키면 다시 반송되는 로직이있어 반송된다면 유효하지않은 이메일이라고 로그를남기고 싶습니다.()




# +배우고 싶은 점
로그를 어떤 메서드에 남기는게 좋을지 몰라서 직접적으로 중요하다고 생각하는 부분에 로그를 남기도록 하였습니다. 로그는 개선할점으로 이후 계속해서 생각해서 commit하겠습니다.

  
