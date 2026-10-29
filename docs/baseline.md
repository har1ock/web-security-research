    Механізм     |  Flask(def)  |  Django(def)  |  FastAPI (def)  |
HttpOnly на сесії|    так       |      так      |    немає сесій взагалі
     SameSite    |немає атрибута|      Lax      |       н/д
       CSP       |    немає     |     немає     |    	немає    
 X-Frame-Options |    немає     |      DENY     |       немає
  CSRF-механізм  |    немає     |    middleware |       немає
