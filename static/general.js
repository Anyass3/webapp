function shownav() {
	document.getElementById('snav').classList.toggle('w3-show');
	// body...
}
function proj() {
	document.getElementById('proj').classList.toggle('w3-show');
	document.getElementById('proj').previousElementSibling.classList.toggle('w3-red');
	// body...
}
function projs() {
	document.getElementById('projs').classList.toggle('w3-show');
	document.getElementById('projs').previousElementSibling.classList.toggle('w3-red');
	// body...
}
function more() {
	document.getElementById('more').classList.toggle('w3-show')
	// body...
}

// Example starter JavaScript for disabling form submissions if there are invalid fields
(function() {
  'use strict';

  window.addEventListener('load', function() {
    var form = document.getElementById('needs-validation');
    form.addEventListener('submit', function(event) {
      if (form.checkValidity() === false) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add('was-validated');
    }, false);
  }, false);
})();