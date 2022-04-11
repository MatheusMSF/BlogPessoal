package org.generation.blogpessoal.service;

import java.nio.charset.Charset;
import java.util.Optional;

import org.apache.tomcat.util.codec.binary.Base64;
import org.generation.blogpessoal.model.Usuario;
import org.generation.blogpessoal.model.UsuarioLogin;
import org.generation.blogpessoal.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class UsuarioService {
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	private String criptografarSenha(String senha) {
		//recebe a senha e cryptografa ela
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		
		return encoder.encode(senha);
	}
	
	public Optional<Usuario>cadastrarUsuario(Usuario usuario){
		//verifica se existe esse usuario.
		if(usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent()) {
			return Optional.empty();
		}
		
		usuario.setSenha(criptografarSenha(usuario.getSenha()));
		
		return Optional.of(usuarioRepository.save(usuario));
	}
	
	private boolean compararSenhas(String senhaDigitada,String senhaDoBanco) {
		
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		
		return encoder.matches(senhaDigitada, senhaDoBanco);
	} 
	
	
	private String geradorBasicToken(String usuario, String senha) {

		String token = usuario + ":" + senha;
		byte[] tokenBase64 = Base64.encodeBase64(token.getBytes(Charset.forName("US-ASCII")));
		
		return "Basic " + new String(tokenBase64);
	}
	
	public Optional<UsuarioLogin> autenticarUsuario(Optional<UsuarioLogin> usuarioLogin){
		
		//Verifica se todas as informacoes do usuario sao do usuario
		
		//Considerando que usuario não tenha dois iguais, puxa todas as informações só pelo usuario que mandei
		Optional<Usuario> usuario = usuarioRepository.findByUsuario(usuarioLogin.get().getUsuario());
		
		if(usuario.isPresent()) {
			// Compara a senha do usuario que eu mandei com o usuario objeto.
			if(compararSenhas(usuarioLogin.get().getSenha(), usuario.get().getSenha())) {

				usuarioLogin.get().setId(usuario.get().getId());
				usuarioLogin.get().setNome(usuario.get().getNome());
				usuarioLogin.get().setUsuario(usuario.get().getUsuario());
				usuarioLogin.get().setFoto(usuario.get().getFoto());
				usuarioLogin.get().setToken(geradorBasicToken(usuarioLogin.get().getUsuario(), usuarioLogin.get().getSenha()));
				usuarioLogin.get().setSenha(usuario.get().getSenha());	
				
				return usuarioLogin;
			}
		}
		
		return Optional.empty();
	}
	
	public Optional<Usuario> atualizarUsuario(Usuario usuario){
		if(usuarioRepository.findById(usuario.getId()).isPresent()) {
			
			//Pelo repositório eu vou buscar todas as informações da pessoa que tiver este usuario.
			Optional<Usuario> buscarUsuario = usuarioRepository.findByUsuario(usuario.getUsuario());
			
			//Vê se existe o alguém com o usuario que a pessoa apertou pra atualizar
			if(buscarUsuario.isPresent()) {
			/*Se entrar aqui significa que a pessoa atualizou o nome do 
				usuário para alguém que já existe, ou não mudou seu usuário, 
				por isso que já existe, nesse último caso o Id vai ser igual e 
				não entra nesse próximo if*/
				if(buscarUsuario.get().getId() != usuario.getId()) {
					
					throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "este usuário já existe!",null);
				}
			}
			
			usuario.setSenha(criptografarSenha(usuario.getSenha()));
			
			return Optional.of(usuarioRepository.save(usuario));
		}
		
		throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Usuário não encontrado!",null);
	}
}
