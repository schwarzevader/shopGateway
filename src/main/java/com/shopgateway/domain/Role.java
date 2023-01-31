package com.shopgateway.domain;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;

//@Entity
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
//@Table(schema = "public")
public class Role implements Serializable, GrantedAuthority {

//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String role;

    @Override
    public String getAuthority() {
        return role;
    }
}