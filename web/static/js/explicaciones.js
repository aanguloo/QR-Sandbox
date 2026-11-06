// Explicaciones en lenguaje simple, para personas sin conocimientos técnicos.
// Una por cada código de hallazgo de src/qrsandbox/senales/hallazgos.py (un test lo revisa).

export const EXPLICACIONES = {
  log_no_coincide: "El dueño del lugar registró su QR con otro destino. Alguien pudo pegar un QR falso encima del original. Es la alerta más fuerte: no pagues ni escribas datos, y avisa al local.",
  log_verificado: "El comercio registró este QR con su firma digital para este lugar. Es una buena señal, aunque no una garantía absoluta: igual revisa lo que te pide la página.",
  lista_negra_url: "Esta dirección ya fue reportada como fraude por investigadores de seguridad.",
  lista_negra_dominio: "Otras páginas de este mismo sitio fueron reportadas como fraude.",
  homoglifos_marca: "Algunas letras del nombre son de otro alfabeto (por ejemplo, una «а» rusa que se ve idéntica a la «a»). A simple vista parece el sitio real, pero es otro.",
  sustitucion_marca: "Cambia letras por números parecidos (0 por o, 1 por l) para imitar un nombre conocido. Los sitios reales no hacen esto.",
  typosquatting_marca: "El nombre se parece mucho al de una marca conocida, pero tiene una o dos letras distintas, esperando que no lo notes.",
  marca_en_dominio_ajeno: "Usa el nombre de una marca, pero el dueño real de la dirección es otro: lo que importa es lo que va justo antes de .cl o .com. Por ejemplo, «bancoestado.cl-seguro.com» pertenece a «cl-seguro.com», no al banco.",
  punycode: "La dirección usa caracteres de otros idiomas. Algunos sitios legítimos lo hacen, pero también sirve para disfrazar direcciones.",
  rastreador_ip: "Al abrirlo, un servicio guarda tu dirección IP (que revela tu ciudad o barrio aproximado) y datos de tu teléfono, y recién después te lleva al destino. Se usa para espiar o preparar estafas.",
  permiso_sensible: "La página quiso usar tu ubicación, la cámara, el micrófono o mandarte notificaciones. Las páginas de estafa lo hacen para rastrearte o llenarte de avisos falsos.",
  userinfo_arroba: "En una dirección web, todo lo que va antes de «@» se ignora. Es un truco para que veas un nombre conocido al principio.",
  ip_literal: "En vez de un nombre (como «banco.cl») usa solo números. Los sitios serios casi nunca hacen esto.",
  sin_https: "La conexión no va cifrada: lo que escribas podría ser visto o cambiado por otros en la red. Nunca escribas claves en un sitio así.",
  tld_riesgoso: "La terminación de la dirección (.xyz, .top, …) es barata y muy usada por estafadores. Por sí sola no prueba nada, pero suma.",
  acortador: "Es un enlace acortado: no se puede saber a dónde lleva sin abrirlo. Justamente por eso lo abrimos nosotros por ti.",
  puerto_no_estandar: "La dirección usa un «puerto» poco común (el número después de los dos puntos). Es raro en sitios normales.",
  muchos_subdominios: "Tiene muchas partes antes del dominio real, para que el comienzo parezca otro sitio.",
  palabras_clave: "Usa palabras como «verificar», «cuenta» o «login» en la dirección: típicas de mensajes que buscan apurarte.",
  dominio_muy_nuevo: "El sitio se creó hace muy pocos días. Los sitios de estafa suelen durar poco antes de que los bloqueen.",
  dominio_nuevo: "El sitio es nuevo (menos de un mes). No es raro en un negocio nuevo, pero suma.",
  certificado_invalido: "El «candado» de seguridad del sitio no es válido. Tu navegador te mostraría una advertencia.",
  certificado_reciente: "El «candado» de seguridad se emitió hace pocos días. Es normal en sitios nuevos, por eso suma poco.",
  marca_en_pagina_ajena: "La página se presenta como una empresa conocida, pero su dirección no es de esa empresa. Es la forma típica del phishing.",
  password_con_marca_ajena: "Te pide tu contraseña haciéndose pasar por otra empresa. Nunca la escribas ahí.",
  formulario_password: "La página pide una contraseña. Antes de escribirla, asegúrate de que sea el sitio correcto.",
  descarga: "Intentó descargar un archivo sin que lo pidieras. Podría ser un programa malicioso.",
  muchas_redirecciones: "Pasa por varios sitios antes de llegar. Los estafadores lo hacen para esconder el destino real.",
  cambio_de_dominio: "Empieza en un sitio y termina en otro distinto.",
  muchos_terceros: "Contacta muchos otros servidores (publicidad o rastreo).",
};

export const QUE_HACER = {
  peligroso: [
    "No abras el enlace ni escribas ningún dato.",
    "Si es un QR pegado en un lugar físico, revisa si hay un sticker encima del original y avísale al local.",
    "Si ya escribiste datos: cambia tu contraseña y llama a tu banco.",
  ],
  sospechoso: [
    "Mejor no lo abras. Si necesitas ese servicio, escribe tú la dirección oficial o usa la app oficial.",
    "Desconfía si te pide pagar, tu RUT, datos de tarjetas o contraseñas.",
  ],
  sin_alertas: [
    "No encontramos señales de riesgo, pero ninguna herramienta es perfecta.",
    "Si te pide pagar o datos personales, revisa que la dirección sea la que esperas.",
  ],
};

export const ICONOS_PERMISO = {
  geolocalizacion: ["📍", "tu ubicación"],
  camara: ["📷", "la cámara"],
  microfono: ["🎤", "el micrófono"],
  notificaciones: ["🔔", "enviarte notificaciones"],
};
