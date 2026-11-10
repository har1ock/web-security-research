| Unnamed: 0   | Unnamed: 1   | p95_ms_avg   | p95_ms_avg.1   | rps_avg   | rps_avg.1   |   RPS_overhead_% |   p95_overhead_% |
|:-------------|:-------------|:-------------|:---------------|:----------|:------------|-----------------:|-----------------:|
| mode         | nan          | secure       | vulnerable     | secure    | vulnerable  |            nan   |            nan   |
| framework    | endpoint     | nan          | nan            | nan       | nan         |            nan   |            nan   |
| django       | greet        | 154.593      | 203.642        | 597.636   | 468.259     |             27.6 |            -24.1 |
| django       | search       | 378.734      | 324.562        | 229.848   | 280.888     |            -18.2 |             16.7 |
| fastapi      | greet        | 108.51       | 84.449         | 798.063   | 907.184     |            -12   |             28.5 |
| fastapi      | search       | 329.958      | 319.736        | 241.752   | 247.808     |             -2.4 |              3.2 |
| flask        | greet        | 112.813      | 87.872         | 675.316   | 868.64      |            -22.3 |             28.4 |
| flask        | search       | 133.112      | 113.881        | 496.469   | 554.486     |            -10.5 |             16.9 |