this.ckan.module('accept-request', function ($) {
    return {
        /* options object can be extended using data-module-* attributes */
        options: {
            action: null,
            user_email: null,
        },

		/* Initialises the module setting up elements and event listeners.
		 *
		 * Returns nothing.
		 */
        initialize: function () {
            $.proxyAll(this, /_on/);
            this.el.on('click', this._onClick);
            var btnAllow = document.getElementById('btnAllow');
        },

		/* Handles the clicking of the request button
		 *
		 * event - An event object.
		 *
		 * Returns nothing.
		 */
        _onClick: function (event) {
            var options = this.options;
            var btnAllow = document.getElementById('btnAllow');
            btnAllow.disabled = true;
            btnAllow.style.opacity=0.5;
            var client = this.sandbox.client;
            function _onClickLoaded(json) {
                location.reload();
                console.log('success');

            };
            client.call('POST', 'restricted_accept_request', {
                request_id: options.request_id,
                resource_id: options.resource_id, user_id: options.user_id,
                request_email: options.request_email
            }, _onClickLoaded);

        }
    };
});