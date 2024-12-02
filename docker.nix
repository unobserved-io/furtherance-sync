{ config, pkgs, ... }:

{

  virtualisation.oci-containers.containers = {
    furtherance-sync = {
      image = "furtherance-sync:self-hosted";
      ports = [
        "8662:8662"
      ];
      environment = {
        POSTGRES_PASSWORD = "dbpassword";
        POSTGRES_USER = "dbuser";
        POSTGRES_DATABASE = "furtherance";
        POSTGRES_PORT = "5432";
        POSTGRES_HOST = "furtherance-db";
      };
      dependsOn = [ "furtherance-db" ];
      extraOptions = [
        "--network=furtherance-net"
      ];
      autoStart = true;
    };

    furtherance-db = {
      image = "postgres:17";
      environment = {
        POSTGRES_DB = "furtherance";
        POSTGRES_USER = "dbuser";
        POSTGRES_PASSWORD = "dbpassword";
      };
      volumes = [
        "furtherance-data:/var/lib/postgresql/data"
      ];
      extraOptions = [
        "--network=furtherance-net"
      ];
      autoStart = true;
    };
  };

}
