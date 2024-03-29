# Emne Eksport

Dette lille programmet ber deg om å logge inn med FEIDE, og vil så opprette en PDF for hvert emne du har tatt (antar forløpig at du kun har tatt fag ved NTNU, men skal være lett å tilpasse).

Veldig nyttig til utveksling eller liknende hvor du har behov for fagbeskrivelser!

Du må ha API tilgang på http://dashboard.dataporten.no/, som var tilgjengelig for alle NTNU-brukere en gang, men kan hende man nå eksplisitt må etterspøøre det.

```bash
> ./emne-eksport --help
Eksporter emnebeskrivelser fra utdanning ved NTNU

Usage: emne-eksport [OPTIONS] -d <DESTINATION> <CLIENT_ID> <CLIENT_SECRET>

Arguments:
  <CLIENT_ID>      OIDC Client ID, can be retrieved from https://dashboard.dataporten.no [env: FEIDE_CLIENT_ID=]
  <CLIENT_SECRET>  OIDC Client Secret, can be retrieved from https://dashboard.dataporten.no [env: FEIDE_CLIENT_SECRET=]

Options:
  -d <DESTINATION>        Name of the folder to put the exported PDFs
  -p <REDIRECT_PORT>      Port of the redirection-URL, which you configured in https://dashboard.dataporten.no [default: 16453]
  -h, --help              Print help information
  -V, --version           Print version information
```

