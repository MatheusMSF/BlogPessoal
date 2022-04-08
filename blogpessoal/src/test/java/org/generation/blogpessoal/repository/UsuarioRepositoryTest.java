package org.generation.blogpessoal.repository;

import java.util.List;
import java.util.Optional;

import org.generation.blogpessoal.model.Usuario;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)//sobe em uma porta aleatória
@TestInstance(TestInstance.Lifecycle.PER_CLASS)/*o Ciclo de vida da Classe de Teste será
por Classe*/
public class UsuarioRepositoryTest {
	
	@Autowired
	private UsuarioRepository repo;
	
	@BeforeAll
	void start() {
		repo.save(new Usuario(0L, 
				"DJ Cleiton Rasta","cleitinho@pedra.com",
				"cabecadegelo",
				"https://imagens.ne10.uol.com.br/veiculos/_midias/jpg/2020/07/10/806x444/1_dj_cleiton_rasta_perfil_body_image_1474918939-16274795.jpg\r\n"));
		repo.save(new Usuario(0L, 
				"DJ user 1","user@padrao.com",
				"senhauser",
				"https://imagens.ne10.uol.com.br/veiculos/_midias/jpg/2020/07/10/806x444/1_dj_cleiton_rasta_perfil_body_image_1474918939-16274795.jpg\r\n"));
		repo.save(new Usuario(0L, 
				"Ola","ola@pedra.com",
				"senhaola",
				"https://imagens.ne10.uol.com.br/veiculos/_midias/jpg/2020/07/10/806x444/1_dj_cleiton_rasta_perfil_body_image_1474918939-16274795.jpg\r\n"));
		repo.save(new Usuario(0L, 
				"eae","eae@pedra.com",
				"senhaeaeee",
				"https://imagens.ne10.uol.com.br/veiculos/_midias/jpg/2020/07/10/806x444/1_dj_cleiton_rasta_perfil_body_image_1474918939-16274795.jpg\r\n"));
	}
	
	@Test
	@DisplayName("Retorna apenas um usuário")
	public void deveRetornarUmUsuario() {
		Optional<Usuario> usuario = repo.findByUsuario("user@padrao.com");
		assertTrue(usuario.get().getUsuario().equals("user@padrao.com"));	
	}
	
	@Test
	@DisplayName("Retorna dois usuários")
	public void deveRetornarDoisUsuarios() {
		List<Usuario> listaDeUsuarios = repo.findAllByNomeContainingIgnoreCase("DJ");
		assertEquals(2, listaDeUsuarios.size());//Compara se o tamanho da lista é do tamanho que eu pedi, 2
		
		assertTrue(listaDeUsuarios.get(0).getNome().equals("DJ Cleiton Rasta"));
		assertTrue(listaDeUsuarios.get(1).getNome().equals("DJ user 1"));
		
	}
	
	@AfterAll
	public void end() {
		repo.deleteAll();
	}

	
	
}
