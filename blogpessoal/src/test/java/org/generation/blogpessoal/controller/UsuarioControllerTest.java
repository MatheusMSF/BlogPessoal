package org.generation.blogpessoal.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;

import org.generation.blogpessoal.model.Usuario;
import org.generation.blogpessoal.service.UsuarioService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)//Teste que se inicia em uma porta aleatória
@TestInstance(TestInstance.Lifecycle.PER_CLASS)//Teste unitário, tem começo meio e fim

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)//Permete passarmos uma ordem para os testes
public class UsuarioControllerTest {
	//Quando vamos testar o controller, usamos o service.
	@Autowired
	private UsuarioService service;
	
	//Coloca TestRestTemplate somente no teste de controller, pois usamos padrão rest que ultiliza
	@Autowired
	private TestRestTemplate testRestTemplate;
	
	@Test
	@Order(1)
	@DisplayName("Cadastrar apenas um usuário")
	public void deveCadastrarUmUsuario() {
		
		//body é o objeto usuario inteiro.
		HttpEntity<Usuario> requisicao = new HttpEntity<Usuario>(new Usuario(0L,"Jose","jose@imperiobronze.com","trabalholindo","https://i.imgur.com/FETvs2O.jpg"));

		
		//exchance(rota que vamos usar pra testar, método http) somente no teste de controlller, pois usamos o padrão rest que utiliza dos verbos e metodos HTTP -> GET-POST-PUT-DELETE

		//TestRestTemplate deixa usarmos os métodos http
		ResponseEntity<Usuario> resposta = testRestTemplate.exchange("/usuarios/cadastrar", HttpMethod.POST, requisicao, Usuario.class);

		assertEquals(HttpStatus.CREATED, resposta.getStatusCode());
		assertEquals(requisicao.getBody().getNome(), resposta.getBody().getNome());
		assertEquals(requisicao.getBody().getUsuario(), resposta.getBody().getUsuario());
		
	}
	
	@Test
	@Order(2)
	@DisplayName("Não deve permitir duplicação do Usuário")
	public void naoDeveDuplicarUsuario() {
		
		service.cadastrarUsuario(new Usuario(0L,"Matheus Santos",
				"mat@santos.com","minhasenha","https://i.imgur.com/FETvs2O.jpg"));
		
		HttpEntity<Usuario> requisicao = new HttpEntity<Usuario>(new Usuario(0L,"Matheus Santos",
				"mat@santos.com","minhasenha","https://i.imgur.com/FETvs2O.jpg"));
		
		ResponseEntity<Usuario> resposta = testRestTemplate
				.exchange("/usuarios/cadastrar", HttpMethod.POST,requisicao,Usuario.class);
		
		assertEquals(HttpStatus.BAD_REQUEST,resposta.getStatusCode());
	}
	
	@Test
	@Order(3)
	@DisplayName("Alterar um Usuário")
	public void deveAtualizarUmUsuario() {
		Optional<Usuario> usuarioCreate = service.cadastrarUsuario(new Usuario(0L,"Luiza",
				"Luiza@Luiza.com","minhasenha","https://i.imgur.com/FETvs2O.jpg"));
		
		Usuario usuarioUpdate = new Usuario(usuarioCreate.get().getId(),
				"Luiza Souza", "Luiza@Lu","minhasenha","https://i.imgur.com/FETvs2O.jpg");
		
		HttpEntity<Usuario> requisicao = new HttpEntity<Usuario>(usuarioUpdate);
		
		ResponseEntity<Usuario> resposta = testRestTemplate
				.withBasicAuth("root", "root")
				.exchange("/usuarios/atualizar", HttpMethod.PUT, requisicao, Usuario.class);
		
		assertEquals(HttpStatus.OK, resposta.getStatusCode());
		assertEquals(usuarioUpdate.getNome(), resposta.getBody().getNome());
		assertEquals(usuarioUpdate.getUsuario(),resposta.getBody().getUsuario());
	}
	
	@Test
	@Order(4)
	@DisplayName("Listar todos os Usuários")
	public void deveMostrarTodosUsuarios() {
		service.cadastrarUsuario(new Usuario(0L,"Matheus Santos",
				"mat@santos.com","minhasenha","https://i.imgur.com/FETvs2O.jpg"));
		
		service.cadastrarUsuario(new Usuario(0L,"Arthur",
				"ar@thur.com","minhasenha","https://i.imgur.com/FETvs2O.jpg"));
		
		ResponseEntity<String> resposta = testRestTemplate
				.withBasicAuth("root", "root")
				.exchange("/usuarios/all", HttpMethod.GET,null,String.class);
		
		assertEquals(HttpStatus.OK, resposta.getStatusCode());
	}
	
}
