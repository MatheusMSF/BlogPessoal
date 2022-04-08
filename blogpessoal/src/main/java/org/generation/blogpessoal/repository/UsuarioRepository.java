package org.generation.blogpessoal.repository;

import java.util.List;
import java.util.Optional;

import org.generation.blogpessoal.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long>{
	
	//Optional é quando pode vir mais do que uma resposta, pode ter ou não o usuario;
	public Optional<Usuario> findByUsuario(String usuario);
	//busca o negócio inteiro, mas não pesquisando pelo Id e sim pelo usuário.
	
	public List<Usuario> findAllByNomeContainingIgnoreCase(String nome);
	
	
}
