package com.gdr.kms;

/**
 * Created by dgollapally on 7/14/16.
 */
public enum KmsRegionEndPoint {
    /** US East (N. Virginia) */
    us_east_1("US East (N. Virginia)", "https://kms.us-east-1.amazonaws.com"),
    /** US West (N. California) */
    us_west_1("US West (N. California)", "https://kms.us-west-1.amazonaws.com"),
    /** US West (Oregon) */
    us_west_2("US West (Oregon)", "https://kms.us-west-2.amazonaws.com"),
    /** Asia Pacific (Mumbai) */
    ap_south_1("Asia Pacific (Mumbai)", "https://kms.ap-south-1.amazonaws.com"),
    /** Asia Pacific (Seoul) */
    ap_northeast_2("Asia Pacific (Seoul)", "https://kms.ap-northeast-2.amazonaws.com"),
    /** Asia Pacific (Singapore) */
    ap_southeast_1("Asia Pacific (Singapore)", "https://kms.ap-southeast-1.amazonaws.com"),
    /** Asia Pacific (Sydney) */
    ap_southeast_2("Asia Pacific (Sydney)", "https://kms.ap-southeast-2.amazonaws.com"),
    /** Asia Pacific (Tokyo) */
    ap_northeast_1("Asia Pacific (Tokyo)", "https://kms.ap-northeast-1.amazonaws.com"),
    /** EU (Frankfurt) */
    eu_central_1("EU (Frankfurt)", "https://kms.eu-central-1.amazonaws.com"),
    /** EU (Ireland) */
    eu_west_1("EU (Ireland)", "https://kms.eu-west-1.amazonaws.com"),
    /** South America (São Paulo) */
    sa_east_1("South America (São Paulo)", "https://kms.sa-east-1.amazonaws.com");


    private final String description;
    private final String url;

    KmsRegionEndPoint(String description, String url) {
        this.description = description;
        this.url = url;
    }

    public String getDescription() {
        return description;
    }

    public String getUrl() {
        return url;
    }
}
