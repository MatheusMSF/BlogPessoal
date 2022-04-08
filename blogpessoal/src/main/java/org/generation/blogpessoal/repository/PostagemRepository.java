package org.generation.blogpessoal.repository;

import java.util.List;

import org.generation.blogpessoal.model.Postagem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostagemRepository extends JpaRepository<Postagem, Long>{
	
	//Isto é o "where" da consulta, aqui estou pedindo pra bucar todos pelo título.
	public List<Postagem> findAllByTituloContainingIgnoreCase(String titulo);
}
