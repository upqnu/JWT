package com.codestates.jwt.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 기본 키 생성을 데이터베이스에 위임. 즉, id 값을 null로 하면 DB가 알아서 AUTO_INCREMENT 해준다.
    private long id;
    private String username;
    private String password;
    private String roles; // User, MANAGER, ADMIN

    public List<String> getRoleList() { // User, MANAGER, ADMIN 등의 역할을 구분
        if(this.roles.length() > 0) {
            return Arrays.asList(this.roles.split(",")); // 일반 배열을 ArrayList로 변환. - 입력된 User, MANAGER, ADMIN 등의 역할을 ,로 구분.
        }
        return new ArrayList<>();
    }
}