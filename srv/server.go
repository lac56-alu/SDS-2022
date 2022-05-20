/*
Servidor
*/
package srv

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sdshttp/util"
	"time"

	"golang.org/x/crypto/argon2"
)

//Almacenamiento de datos
//var usuariosRegistrados []user

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// ejemplo de tipo para un usuario
type user struct {
	Name     string            // nombre de usuario
	Username string            // nick del usuario
	Email    string            // email de usuario
	Hash     []byte            // hash de la contraseña
	Salt     []byte            // sal para la contraseña
	Token    []byte            // token de sesión
	Seen     time.Time         // última vez que fue visto
	Data     map[string]string // datos adicionales del usuario
}

/*type User1 struct {
	Nombre   string `json:"nombre"`
	Username string `json:"userName"`
	Email    string `json:"email"`
	Password string `json:"password"`
}*/

type respuestaServer struct {
	Ok    string `json:"Ok"`
	Msg   string `json:"Msg"`
	Token string `json:"token"`
}

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user

// gestiona el modo servidor
func Run() {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios

	http.HandleFunc("/", handler) // asignamos un handler global

	//Mis llamadas
	http.HandleFunc("/register", registro)
	//http.HandleFunc("/login", login)

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                                                   // es necesario parsear el formulario
	w.Header().Set("Content-Type", "application/json; charset=UTF-8") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "login": // ** login
		u, ok := gUsers[req.Form.Get("userName")] // ¿existe ya el usuario?

		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(202)
			return
		} else {
			password := util.Decode64(req.Form.Get("pass")) // obtenemos la contraseña (keyLogin)
			hash := argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)

			if !bytes.Equal(u.Hash, hash) { // comparamos
				//response(w, false, "Credenciales inválidas", nil)
				w.WriteHeader(203)
			} else {
				u.Seen = time.Now()        // asignamos tiempo de login
				u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
				rand.Read(u.Token)         // el token es aleatorio
				gUsers[u.Name] = u
				response(w, true, "Credenciales válidas", u.Token)
				w.WriteHeader(200)
			}
		}

	case "data": // ** obtener datos de usuario
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else if !bytes.EqualFold(u.Token, util.Decode64(req.Form.Get("token"))) {
			// token no coincide
			response(w, false, "No autentificado", nil)
			return
		}

		datos, err := json.Marshal(&u.Data) //
		chk(err)
		u.Seen = time.Now()
		gUsers[u.Name] = u
		response(w, true, string(datos), u.Token)

	case "registro":
		/*
			fmt.Printf("\n - Nombre Usuario: %q", req.Form.Get("nombre"))
			fmt.Printf("\n - Password: %q", req.Form.Get("pass"))
			fmt.Printf("\n - Email Codificado: %q", req.Form.Get("email"))
			fmt.Printf("\n - Email Decodificado: %q", util.Decode64(req.Form.Get("email")))
		*/

		nombreRegistro := req.Form.Get("nombre")
		usernameRegistro := req.Form.Get("username")
		passRegistro := req.Form.Get("pass")
		emailRegistro := req.Form.Get("email")
		//keyDataRegistro := req.Form.Get("keyData")
		publicKeyRegistro := req.Form.Get("publicKey")
		privateKeyRegistro := req.Form.Get("privateKey")

		_, ok := gUsers[usernameRegistro] // ¿existe ya el usuario?
		if ok {
			w.WriteHeader(400)
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = nombreRegistro
		u.Email = emailRegistro
		u.Username = usernameRegistro
		u.Salt = make([]byte, 16)              // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                      // la sal es aleatoria
		u.Data = make(map[string]string)       // reservamos mapa de datos de usuario
		u.Data["private"] = privateKeyRegistro // clave privada
		u.Data["public"] = publicKeyRegistro   // clave pública
		//u.Data["keyData"] = keyDataRegistro
		password := util.Decode64(passRegistro) // contraseña (keyLogin)

		// Argon2
		u.Hash = argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)

		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio
		//fmt.Printf("\n Token: %q", u.Token)

		gUsers[u.Username] = u
		w.WriteHeader(200)
		//w.Header().Set("Authoritation", util.Encode64([]byte(u.Token)))
		response(w, true, string("Te has registrado correctamente"), u.Token)

	case "create":
		nombre := string(util.Decode64(req.Form.Get("username")))
		u, ok := gUsers[nombre] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			fmt.Println("hola1")
			w.WriteHeader(202)
			return
		} else {
			fmt.Println("hola2")
			texto := req.Form.Get("Texto")
			nom := req.Form.Get("NombreFichero")
			fmt.Println(u.Name)
			//path := "C:\\Users\\Adel\\Desktop\\2122\\SDS\\ficheros\\" + u.Name
			path := "F:\\ServidorSDS \\" + u.Name
			_, erro := os.Stat(path)
			if os.IsNotExist(erro) {
				erro = os.Mkdir(path, 0755)
			}
			f, err := os.Create(path + "\\" + nom + ".txt")
			if err != nil {
				w.WriteHeader(201)
				return
			} else {
				fmt.Fprintln(f, texto)
				f.Close()
				w.WriteHeader(200)
			}
		}
	case "lectura":

	case "listarFicheros":
		archivos, err := ioutil.ReadDir("F:\\ServidorSDS")
		if err != nil {
			log.Fatal(err)
		}
		for _, archivo := range archivos {
			fmt.Println("Nombre:", archivo.Name())
			fmt.Println("Tamaño:", archivo.Size())
			fmt.Println("Modo:", archivo.Mode())
			fmt.Println("Ultima modificación:", archivo.ModTime())
			fmt.Println("Es directorio?:", archivo.IsDir())
			fmt.Println("-----------------------------------------")
		}

	default:
		response(w, false, "Comando no implementado", nil)
	}

}

// respuesta del servidor
// (empieza con mayúscula ya que se utiliza en el cliente también)
// (los variables empiezan con mayúscula para que sean consideradas en el encoding)
type Resp struct {
	Ok    bool   // true -> correcto, false -> error
	Msg   string // mensaje adicional
	Token []byte // token de sesión para utilizar por el cliente
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	fmt.Printf("\n Token: %q", token)
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

//Mis llamadas
func registro(w http.ResponseWriter, req *http.Request) {

	/*var usuario User1
	json.NewDecoder(req.Body).Decode(&usuario)

	fmt.Printf("\nNombre Usuario: %q", usuario.Nombre)
	*/
}
