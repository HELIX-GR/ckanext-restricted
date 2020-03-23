this.ckan.module('reject-request', function ($) {
    return {
        /* options object can be extended using data-module-* attributes */
        options: {
            action: null,
            user_id: null,
            user_email: null,
        },

		/* Initialises the module setting up elements and event listeners.
		 *
		 * Returns nothing.
		 */
        initialize: function () {
            $.proxyAll(this, /_on/);
            this.el.on('click', this._onClick);
            var btnDeny = document.getElementById('btnDeny');
        },

		/* Handles the clicking of the request button
		 *
		 * event - An event object.
		 *
		 * Returns nothing.
		 */
        _onClick: function (event) {
            var options = this.options;
            var btnDeny = document.getElementById('btnDeny');
            btnDeny.disabled = true;
            btnDeny.style.opacity=0.5;
            var options = this.options;

            var client = this.sandbox.client;
            function _onClickLoaded (json) {
                location.reload();
                console.log('success, deleted');
                
            };
            console.log(options.request_id);
            client.call('POST', 'restricted_reject_request', { request_id: options.request_id, resource_id: options.resource_id, user_id: options.user_id},_onClickLoaded);

        }
    };
});