package org.generation.blogpessoal.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	//faz um usuario na memoria padrão para facilitar o teste
	@Override
	// auth é alias apelido para a clase AuthenticationManagerBuilder
	protected void configure(AuthenticationManagerBuilder auth) throws Exception { // protected a função está acessivel a todos os níveis de segurança, todos os pacotes de segurança tem acesso ao usuario em memoria
		auth.userDetailsService(userDetailsService);
		
		auth.inMemoryAuthentication()//caso queira logar com usuario in Memory também consegue
		.withUser("root")//identificando usuario
		.password(passwordEncoder().encode("root"))//identificando senha
		.authorities("ROLE_USER");//indica o que o root root significa na aplicação
		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		//criptografando a senha
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		//Auroriza as requisições da aplicação
		http.authorizeHttpRequests()
		//idependente de estar logado ou não, permite cadastrar/logar
		.antMatchers("/usuarios/logar").permitAll()
		.antMatchers("/usuarios/cadastrar").permitAll()
		//o que estiver autorizado vai entrar
		.antMatchers(HttpMethod.OPTIONS).permitAll()	
		//qualquer requisição, tirando cadastrar e logar, vai precisar de autorização
		.anyRequest().authenticated()
		//está sendo feito atraves dos metodos HTTP
		.and().httpBasic()
		//o token não dura pra sempre.
		.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and().cors() // auxiliar do cross origin. permitindo de qq rota
		//não deixa atualizar ou deletar a aplicação
		.and().csrf().disable();

	}
	
}
