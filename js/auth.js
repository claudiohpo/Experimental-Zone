const loginForm = document.getElementById("loginForm");
const loginMsg = document.getElementById("loginMsg");
const openRegister = document.getElementById("openRegister");
const openRecover = document.getElementById("openRecover");
const overlayRegister = document.getElementById("overlayRegister");
const registerForm = document.getElementById("registerForm");

// novos elementos (recuperação)
const overlayRecover = document.getElementById("overlayRecover");
const recoverForm = document.getElementById("recoverForm");
const overlayRecoverResult = document.getElementById("overlayRecoverResult");

function showOverlay(el) {
  el.classList.add("show");
  el.setAttribute("aria-hidden", "false");
}
function hideOverlay(el) {
  el.classList.remove("show");
  el.setAttribute("aria-hidden", "true");
}

openRegister.addEventListener("click", () => showOverlay(overlayRegister));
// openRecover.addEventListener("click", () => { alert("Recuperação de senha será implementada em breve."); });
openRecover.addEventListener("click", () => showOverlay(overlayRecover));

document
  .getElementById("regCancel")
  .addEventListener("click", () => hideOverlay(overlayRegister));

// Função para tratar a resposta da API
async function parseResponse(res) {
  const text = await res.text().catch(() => "");
  try {
    return text ? JSON.parse(text) : {};
  } catch (e) {
    return { error: text || "Resposta inválida do servidor" };
  }
}

// Função para registrar um novo usuário
registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("regUsername").value.trim();
  const email = document.getElementById("regEmail").value.trim();
  const password = document.getElementById("regPassword").value;
  const password2 = document.getElementById("regPassword2").value;
  const msgEl = document.getElementById("regMsg");

  msgEl.style.color = "#333";
  msgEl.textContent = "Enviando...";

  if (!username || !email || !password) {
    msgEl.style.color = "red";
    msgEl.textContent = "Preencha todos os campos.";
    return;
  }

  if (password !== password2) {
    msgEl.style.color = "red";
    msgEl.textContent = "Senhas não conferem.";
    return;
  }

  try {
    const res = await fetch("/api/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ action: "register", username, email, password }),
    });

    const body = await parseResponse(res);

    if (!res.ok) {
      msgEl.style.color = "red";
      msgEl.textContent = body.error || `Erro ${res.status}`;
      console.error("Cadastro falhou:", body);
      return;
    }

    msgEl.style.color = "green";
    msgEl.textContent = "Cadastro concluído. Faça login.";
    setTimeout(() => hideOverlay(overlayRegister), 1000);
  } catch (err) {
    console.error("Erro fetch /api/users register:", err);
    msgEl.style.color = "red";
    msgEl.textContent = "Erro de conexão com o servidor.";
  }
});

// Função para login
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;
  loginMsg.style.color = "#333";
  loginMsg.textContent = "Validando...";

  if (!username || !password) {
    loginMsg.style.color = "red";
    loginMsg.textContent = "Preencha usuário e senha.";
    return;
  }

  try {
    const res = await fetch("/api/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ action: "login", username, password }),
    });

    const body = await parseResponse(res);

    if (!res.ok) {
      loginMsg.style.color = "red";
      loginMsg.textContent = body.error || `Falha no login (${res.status})`;
      console.error("Login falhou:", body);
      return;
    }

    // grava sessão somente em sessionStorage (não persiste entre janelas)
    sessionStorage.setItem("km_username", username);

    // redireciona para página original se fornecida
    const params = new URLSearchParams(window.location.search);
    const redirect = params.get("redirect");
    if (redirect) {
      try {
        const decoded = decodeURIComponent(redirect);
        window.location.href = decoded;
        return;
      } catch (err) {
        console.warn(
          "Erro ao decodificar redirect, redirecionando para app.html",
          err
        );
      }
    }

    window.location.href = "app.html";
  } catch (err) {
    console.error("Erro fetch /api/users login:", err);
    loginMsg.style.color = "red";
    loginMsg.textContent = "Erro de conexão com o servidor.";
  }
});

// ---- Recuperação de senha ----
document.getElementById("recCancel").addEventListener("click", () => {
  // limpar campos e mensagem
  document.getElementById("recUsername").value = "";
  document.getElementById("recEmail").value = "";
  document.getElementById("recMsg").textContent = "";
  hideOverlay(overlayRecover);
});

recoverForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("recUsername").value.trim();
  const email = document.getElementById("recEmail").value.trim();
  const msgEl = document.getElementById("recMsg");

  msgEl.style.color = "#333";
  msgEl.textContent = "Consultando...";

  if (!username || !email) {
    msgEl.style.color = "red";
    msgEl.textContent = "Preencha usuário e email.";
    return;
  }

  try {
    const res = await fetch("/api/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ action: "recover", username, email }),
    });

    const body = await parseResponse(res);

    if (!res.ok) {
      msgEl.style.color = "red";
      // mensagem amigável definida pelo servidor ou genérica
      msgEl.textContent = body.error || `Erro ${res.status}`;
      console.error("Recuperação falhou:", body);
      return;
    }

    // // sucesso: body.password contém a senha
    // const senha = body.password || "";
    // hideOverlay(overlayRecover);

    // // preenche e mostra o overlay de resultado
    // document.getElementById("recResultUser").textContent = username;
    // document.getElementById("recResultPassword").textContent = senha;
    // showOverlay(overlayRecoverResult);

    // sucesso: body.password contém a senha
    // const senha = body.password || "";
    // hideOverlay(overlayRecover);
    // === Modificação em js/auth.js (no handler recoverForm.addEventListener)
    if (!res.ok) {
      msgEl.style.color = "red";
      msgEl.textContent = body.error || `Erro ${res.status}`;
      console.error("Recuperação falhou:", body);
      return;
    }

    // sucesso: não mostrar senha
    hideOverlay(overlayRecover);
    document.getElementById("recResultUser").textContent = username || "";
    document.getElementById("recResultPassword").value = ""; // limpar
    document.getElementById("recResultNote").textContent =
      "Se houver uma conta com esses dados, um link de recuperação foi enviado para o e-mail cadastrado (se configurado).";
    showOverlay(overlayRecoverResult);

    // preenche e mostra o overlay de resultado
    document.getElementById("recResultUser").textContent = username;

    // preenche o input (mantendo type="password" por padrão)
    const resultInput = document.getElementById("recResultPassword");
    resultInput.type = "password";
    resultInput.value = senha;

    showOverlay(overlayRecoverResult);
  } catch (err) {
    console.error("Erro fetch /api/users recover:", err);
    msgEl.style.color = "red";
    msgEl.textContent = "Erro de conexão com o servidor.";
  }
});

// document.getElementById("recResultOk").addEventListener("click", () => {
//   // fecha pop-up de resultado e limpa campos
//   hideOverlay(overlayRecoverResult);
//   document.getElementById("recUsername").value = "";
//   document.getElementById("recEmail").value = "";
//   document.getElementById("recMsg").textContent = "";
// });

document.getElementById("recResultOk").addEventListener("click", () => {
  hideOverlay(overlayRecoverResult);

  // limpa campos de recuperação e o campo de resultado
  document.getElementById("recUsername").value = "";
  document.getElementById("recEmail").value = "";
  document.getElementById("recMsg").textContent = "";
  const resultInput = document.getElementById("recResultPassword");
  if (resultInput) resultInput.value = "";
});

// SVGs usados no botão
const svgEyeOpen = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
  <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/>
  <circle cx="12" cy="12" r="3.2" fill="currentColor" />
</svg>`;

const svgEyeClosed = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
  <path d="M17.94 17.94A10.95 10.95 0 0 1 12 19c-7 0-11-7-11-7 1.38-3.73 4.58-6.35 8.45-6.85" />
  <path d="M22.54 16.88A20.22 20.22 0 0 0 23 12s-4-7-11-7c-1.97 0-3.84.45-5.53 1.24" />
  <path d="M1 1l22 22" stroke="currentColor" />
</svg>`;

/*
  Setup: procura inputs com data-password-toggle e insere/reutiliza botões .password-toggle
  - se input não estiver dentro de .password-wrapper, o script cria o wrapper automaticamente
  - usa aria-pressed/aria-label para acessibilidade
*/
(function setupPasswordToggles() {
  const inputs = document.querySelectorAll("input[data-password-toggle]");

  inputs.forEach((input) => {
    // garantir que o input esteja dentro de um .password-wrapper
    let wrapper = input.closest(".password-wrapper");
    if (!wrapper) {
      // criar wrapper e mover input para dentro
      wrapper = document.createElement("div");
      wrapper.className = "password-wrapper";
      input.parentNode.insertBefore(wrapper, input);
      wrapper.appendChild(input);
    }

    // procurar botão existente, se não existir criar
    let btn = wrapper.querySelector(".password-toggle");
    if (!btn) {
      btn = document.createElement("button");
      btn.type = "button";
      btn.className = "password-toggle";
      btn.setAttribute("aria-label", "Mostrar senha");
      btn.setAttribute("aria-pressed", "false");
      wrapper.appendChild(btn);
    }

    // inicializar ícone (olho aberto -> senha oculta por padrão)
    btn.innerHTML = svgEyeOpen;
    btn.setAttribute("aria-pressed", "false");
    btn.setAttribute("aria-label", "Mostrar senha");

    // clique no botão alterna input.type e ícone
    btn.addEventListener("click", function () {
      const isPassword = input.type === "password";
      if (isPassword) {
        input.type = "text";
        btn.innerHTML = svgEyeClosed; // ícone olho fechado (senha visível)
        btn.setAttribute("aria-pressed", "true");
        btn.setAttribute("aria-label", "Ocultar senha");
      } else {
        input.type = "password";
        btn.innerHTML = svgEyeOpen; // ícone olho aberto (senha oculta)
        btn.setAttribute("aria-pressed", "false");
        btn.setAttribute("aria-label", "Mostrar senha");
      }
    });

    // função para manter o foco no botão após clicar
    btn.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        btn.click();
      }
    });
  });
})();
