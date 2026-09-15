package au.edu.oshc.smartguide;

import jakarta.persistence.*;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

@Entity
@Table(name="app_users")
class User {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
    @Column(unique=true, nullable=false) String email;
    @Column(nullable=false) String passwordHash;
    String mfaSecret;
    boolean mfaEnabled;
    String fullName;
    String address;
    String birthdate;
    String phoneNumber;
    @Lob @Column(columnDefinition="CLOB") String photoData;
    String role = "STUDENT";

    public Long getId(){return id;}
    public String getEmail(){return email;} public void setEmail(String x){email=x;}
    public String getPasswordHash(){return passwordHash;} public void setPasswordHash(String x){passwordHash=x;}
    public String getMfaSecret(){return mfaSecret;} public void setMfaSecret(String x){mfaSecret=x;}
    public boolean isMfaEnabled(){return mfaEnabled;} public void setMfaEnabled(boolean x){mfaEnabled=x;}
    public String getFullName(){return fullName;} public void setFullName(String x){fullName=x;}
    public String getAddress(){return address;} public void setAddress(String x){address=x;}
    public String getBirthdate(){return birthdate;} public void setBirthdate(String x){birthdate=x;}
    public String getPhoneNumber(){return phoneNumber;} public void setPhoneNumber(String x){phoneNumber=x;}
    public String getPhotoData(){return photoData;} public void setPhotoData(String x){photoData=x;}
    public String getRole(){return role;} public void setRole(String x){role=x;}
}

interface UserRepository extends JpaRepository<User,Long>{ Optional<User> findByEmail(String email); }

@Entity @Table(name="progress")
class Progress {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
    @Column(unique=true) String email;
    @Lob String json;
    public String getEmail(){return email;} public void setEmail(String x){email=x;}
    public String getJson(){return json;} public void setJson(String x){json=x;}
}
interface ProgressRepository extends JpaRepository<Progress,Long>{ Optional<Progress> findByEmail(String email); }


@Entity
@Table(name="data_tokens", indexes={
        @Index(name="idx_data_token_token", columnList="token", unique=true),
        @Index(name="idx_data_token_owner", columnList="ownerEmail")
})
class DataToken {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
    Long id;

    @Column(nullable=false, unique=true, length=80)
    String token;

    @Column(nullable=false, length=320)
    String ownerEmail;

    @Column(nullable=false, length=80)
    String fieldName;

    @Lob @Column(nullable=false, columnDefinition="CLOB")
    String ciphertext;

    public String getToken(){return token;}
    public void setToken(String x){token=x;}
    public String getOwnerEmail(){return ownerEmail;}
    public void setOwnerEmail(String x){ownerEmail=x;}
    public String getFieldName(){return fieldName;}
    public void setFieldName(String x){fieldName=x;}
    public String getCiphertext(){return ciphertext;}
    public void setCiphertext(String x){ciphertext=x;}
}

interface DataTokenRepository extends JpaRepository<DataToken,Long> {
    Optional<DataToken> findByTokenAndOwnerEmailAndFieldName(
            String token, String ownerEmail, String fieldName);

    void deleteByToken(String token);

    long deleteByOwnerEmail(String ownerEmail);

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query(
            "update DataToken d set d.ownerEmail = :newEmail where d.ownerEmail = :oldEmail")
    int updateOwnerEmail(
            @org.springframework.data.repository.query.Param("oldEmail") String oldEmail,
            @org.springframework.data.repository.query.Param("newEmail") String newEmail);
}
