package org.generation.blogpessoal.repository;

import java.util.Optional;

import org.generation.blogpessoal.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long>{
	
	//Optional é quando pode vir mais do que uma resposta, pode ter ou não o usuario;
	public Optional<Usuario> findByUsuario(String usuario);
}
