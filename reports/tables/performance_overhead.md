| Unnamed: 0   | Unnamed: 1   | p95_ms_avg   | p95_ms_avg.1   | rps_avg   | rps_avg.1   |   RPS_overhead_% |   p95_overhead_% |
|:-------------|:-------------|:-------------|:---------------|:----------|:------------|-----------------:|-----------------:|
| mode         | nan          | secure       | vulnerable     | secure    | vulnerable  |            nan   |            nan   |
| framework    | endpoint     | nan          | nan            | nan       | nan         |            nan   |            nan   |
| django       | greet        | 176.599      | 218.803        | 553.993   | 452.177     |            -22.5 |            -19.3 |
| django       | search       | 501.5        | 287.058        | 173.584   | 311.458     |             44.3 |             74.7 |
| fastapi      | greet        | 87.41        | 95.706         | 881.132   | 890.184     |              1   |             -8.7 |
| fastapi      | search       | 327.299      | 296.338        | 257.0     | 286.149     |             10.2 |             10.4 |
| flask        | greet        | 117.173      | 90.527         | 720.204   | 877.208     |             17.9 |             29.4 |
| flask        | search       | 181.339      | 170.177        | 468.472   | 558.843     |             16.2 |              6.6 |