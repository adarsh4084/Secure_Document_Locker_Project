(() => {
  const menuToggle = document.querySelector('[data-menu-toggle]');
  const nav = document.querySelector('.main-nav');
  if (menuToggle && nav) {
    menuToggle.addEventListener('click', () => {
      const open = nav.classList.toggle('nav-open');
      menuToggle.setAttribute('aria-expanded', String(open));
    });
  }

  document.querySelectorAll('[data-flash-close]').forEach((button) => {
    button.addEventListener('click', () => button.closest('[data-flash]')?.remove());
  });

  document.querySelectorAll('[data-toggle-password]').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      button.textContent = showing ? 'Show' : 'Hide';
      button.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
      input.focus();
    });
  });

  const passwordInput = document.querySelector('[data-password-check]');
  if (passwordInput) {
    const rules = {
      length: (value) => value.length >= 10,
      upper: (value) => /[A-Z]/.test(value),
      number: (value) => /[0-9]/.test(value),
      symbol: (value) => /[^A-Za-z0-9]/.test(value),
    };
    const updateRules = () => {
      Object.entries(rules).forEach(([name, validator]) => {
        document.querySelector(`[data-rule="${name}"]`)?.classList.toggle('rule-good', validator(passwordInput.value));
      });
      const confirm = document.querySelector('[data-confirm-password]');
      const message = document.querySelector('[data-confirm-message]');
      if (confirm && message) {
        const matches = confirm.value.length > 0 && confirm.value === passwordInput.value;
        message.textContent = confirm.value.length === 0 ? 'Use the same password in both fields.' : (matches ? 'Passwords match.' : 'Passwords do not match yet.');
        message.style.color = confirm.value.length === 0 ? '' : (matches ? '#229f77' : '#d95365');
      }
    };
    passwordInput.addEventListener('input', updateRules);
    document.querySelector('[data-confirm-password]')?.addEventListener('input', updateRules);
    document.querySelector('[data-password-form]')?.addEventListener('submit', (event) => {
      const confirm = document.querySelector('[data-confirm-password]');
      const valid = Object.values(rules).every((validator) => validator(passwordInput.value));
      if (!valid || !confirm || confirm.value !== passwordInput.value) {
        event.preventDefault();
        updateRules();
        (valid ? confirm : passwordInput)?.focus();
      }
    });
    updateRules();
  }

  const pinInput = document.querySelector('[data-pin-input]');
  const pinConfirm = document.querySelector('[data-pin-confirm]');
  const pinMessage = document.querySelector('[data-pin-message]');
  const sanitizePin = (input) => {
    if (!input) return;
    input.value = input.value.replace(/[^0-9]/g, '').slice(0, 6);
  };
  if (pinInput) pinInput.addEventListener('input', () => sanitizePin(pinInput));
  if (pinConfirm) pinConfirm.addEventListener('input', () => sanitizePin(pinConfirm));
  document.querySelector('[data-pin-form]')?.addEventListener('submit', (event) => {
    sanitizePin(pinInput);
    sanitizePin(pinConfirm);
    if (!pinInput || !pinConfirm || !/^\d{6}$/.test(pinInput.value) || pinInput.value !== pinConfirm.value) {
      event.preventDefault();
      if (pinMessage) {
        pinMessage.textContent = 'Enter the same six digits in both fields.';
        pinMessage.style.color = '#d95365';
      }
      (pinInput && pinInput.value.length === 6 ? pinConfirm : pinInput)?.focus();
    }
  });
  document.querySelector('[data-pin-verify-form]')?.addEventListener('submit', (event) => {
    const input = document.querySelector('[data-pin-input]');
    sanitizePin(input);
    if (!input || !/^\d{6}$/.test(input.value)) {
      event.preventDefault();
      input?.focus();
    }
  });

  const fileInput = document.querySelector('[data-file-input]');
  const fileDropzone = document.querySelector('[data-file-dropzone]');
  const fileName = document.querySelector('[data-file-name]');
  if (fileInput && fileName) {
    fileInput.addEventListener('change', () => {
      const file = fileInput.files?.[0];
      fileName.textContent = file ? file.name : 'Choose a document to protect';
      if (file) {
        const title = document.getElementById('title');
        if (title && !title.value.trim()) {
          title.value = file.name.replace(/\.[^.]+$/, '').replace(/[_-]+/g, ' ').trim().slice(0, 100);
        }
      }
    });
  }
  if (fileDropzone && fileInput) {
    ['dragenter', 'dragover'].forEach((eventName) => fileDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      fileDropzone.classList.add('drag-active');
    }));
    ['dragleave', 'drop'].forEach((eventName) => fileDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      fileDropzone.classList.remove('drag-active');
    }));
    fileDropzone.addEventListener('drop', (event) => {
      const files = event.dataTransfer?.files;
      if (files && files.length) {
        try {
          fileInput.files = files;
          fileInput.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (_) {
          // Some browsers restrict assignment to file inputs. The normal chooser still works.
        }
      }
    });
  }

  document.querySelector('[data-upload-form]')?.addEventListener('submit', () => {
    const button = document.querySelector('[data-upload-submit]');
    if (button) {
      button.disabled = true;
      button.innerHTML = '<span class="button-upload-icon">⌑</span> Encrypting & saving…';
    }
  });
})();
