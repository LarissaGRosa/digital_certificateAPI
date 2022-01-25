package service.labsec_service_challenge.payloads;


import javax.validation.constraints.NotBlank;

public class SubjectRequest {
    @NotBlank
    private String CN;

    @NotBlank
    private String OU;

    @NotBlank
    private String O;

    @NotBlank
    private String L;

    @NotBlank
    private String ST;

    @NotBlank
    private String C;

    @NotBlank
    private String UI;

    private Long auth_id;
    public String getCN() {
        return CN;
    }

    public void setCN(String CN) {
        this.CN = CN;
    }

    public String getO() {
        return O;
    }

    public void setO(String o) {
        O = o;
    }

    public String getOU() {
        return OU;
    }

    public void setOU(String OU) {
        this.OU = OU;
    }

    public String getL() {
        return L;
    }

    public void setL(String l) {
        L = l;
    }

    public String getST() {
        return ST;
    }

    public void setST(String ST) {
        this.ST = ST;
    }

    public String getC() {
        return C;
    }

    public void setC(String c) {
        C = c;
    }

    public String getUI() {
        return UI;
    }

    public void setUI(String UI) {
        this.UI = UI;
    }

    public Long getAuth_id() {
        return auth_id;
    }

    public void setAuth_id(Long auth_id) {
        this.auth_id = auth_id;
    }
}
