const axios = require('axios');

async function getGeoLocation(ipAddress) {
    const defaultData = { ip: ipAddress, city: 'Unknown', country: 'Unknown', lat: 0, lon: 0, isp: 'Unknown' };
    if (!ipAddress) return defaultData;

    try {
        const response = await axios.get(`http://ip-api.com/json/${ipAddress}`);
        const data = response.data;
        if (data.status !== 'success') return defaultData;

        return {
            ip: ipAddress,
            city: data.city || 'Unknown',
            country: data.country || 'Unknown',
            lat: data.lat || 0,
            lon: data.lon || 0,
            isp: data.isp || 'Unknown'
        };
    } catch (error) {
        return defaultData;
    }
}

module.exports = { getGeoLocation };